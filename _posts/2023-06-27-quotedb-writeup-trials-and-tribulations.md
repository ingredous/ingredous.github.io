---
layout: post
title: QuoteDB Exploit Challenge - Trials & Tribulations
tags: [Research, RE]
author: mqt @ Ingredous Labs
comment: true
---
## Preface

The point of this blog post is to provide a postmortem highlighting some of the mistakes which were encountered while solving the `QuoteDB` challenge which can be found in the following [Github Repo](https://github.com/bmdyy/quote_db).

## Format String Vulnerability

The application includes a `get_quote` feature, which enables the client to input a quote index, triggering a response from the server with the corresponding quote. An initial call to the `get_quote()` function can be discovered at `main + 0xEF6`. A detailed examination of the function's disassembly reveals a call to `_snprintf()`:

```text
.text:0131158E mov     eax, [ebp+arg_0]
.text:01311591 shl     eax, 0Bh
.text:01311594 lea     edx, _quotes[eax]
.text:0131159A mov     eax, [ebp+arg_4]
.text:0131159D mov     eax, [eax]
.text:0131159F mov     [esp+8], edx    ; Format
.text:013115A3 mov     dword ptr [esp+4], 800h ; BufferCount
.text:013115AB mov     [esp], eax      ; Buffer
.text:013115AE call    _snprintf
```

What stands out in this specific instance of `snprintf()` invocation is the absence of any additional arguments passed to the function, coupled with the eventual discovery that the format string specifier could be controlled by the attacker. These two factors (mostly the latter) together render this call a potent hotspot for a format string vulnerability.

As mentioned above, the format string specifier can contain attacker controlled input. To explain how this happens, it's worth stepping back for a second. Apart from the `get_quote` functionality, the application offers the following additional functionalities:

- `add_quote`
- `update_quote`
- `delete_quote`

To understand what's being passed to the `snprintf()` call, let's do two things, the first is examining the `snprintf()` function prototype:

```c
int snprintf ( char * s, size_t n, const char * format, ... );
```

The second is examining the stack at the time of the call to learn more about the arguments:

(Note: In this example, a packet was sent to instruct the application to read the quote that is associated with index 1)

```text
main+0x15ae:
00b715ae e8fd150000      call    main!main+0xd27 (00b72bb0)
0:002> dds esp L3
01db7390  015b4648
01db7394  00000800
01db7398  00b80280 main!main+0xe3f7
```

Using the function signature above, the arguments can be identified:

`0x015b4648` => destination buffer
`0x800` => size of copy
`0x00b80280` => format string pointer

Displaying the ASCII contents of the format string pointer shows the following:

```text
0:002> da 0x00b80280
00b80280  "Give a man a mask and he'll tell"
00b802a0  " you the truth. - Oscar Wilde"
```

Stepping over the `snprintf()` call, and displaying the contents of the destination buffer shows it was overwritten with the string:

```text
0:002> db 0x015b4648
015b4648  47 69 76 65 20 61 20 6d-61 6e 20 61 20 6d 61 73  Give a man a mas
015b4658  6b 20 61 6e 64 20 68 65-27 6c 6c 20 74 65 6c 6c  k and he'll tell
015b4668  20 79 6f 75 20 74 68 65-20 74 72 75 74 68 2e 20   you the truth. 
015b4678  2d 20 4f 73 63 61 72 20-57 69 6c 64 65 00 ad ba  - Oscar Wilde...
```

Let's now introduce a modified packet that will reassign the quote at index 1 to a format specifier by leveraging the `update_functionality` mentioned earlier - in this case, updating the quote to include three `%p` specifiers which should return three hex values.

After sending the packet which instructs the application to update the quote, let's retrigger the `get_quote()` functionality and examine the stack at the time of the call to `snprintf()`:

```text
main+0x15ae:
00b715ae e8fd150000      call    main!main+0xd27 (00b72bb0)
0:002> dds esp L3
021b7564  015b4e60
021b7568  00000800
021b756c  00b80280 main!main+0xe3f7
```

Displaying the ASCII contents of the format string specifier reveals:

```text
0:002> da 00b80280 
00b80280  "%p %p %p"
```

This validates the hypothesis that an attacker is capable of controlling the format string specifier. Following this, let's take a closer look what is written to the destination buffer after stepping over the `snprintf()` call:

```text
0:002> db 015b4e60
015b4e60  37 37 30 61 36 36 62 30-20 30 30 30 30 30 33 38  770a66b0 0000038
015b4e70  35 20 30 30 62 37 31 37-33 62 00 ba 0d f0 ad ba  5 00b7173b......
```

The output clearly reveals that three `DWORD` values have been written into the destination buffer. This confirms the successful exploitation of the format string vulnerability. Subsequently, the contents of the destination buffer are sent back to the client, which further enhances the value of this read primitive, at the application has been compiled with `Address Space Layout Randomization (ASLR)`.

Should there be any curiosity regarding the potential of this `snprintf(`) invocation to overwrite a return address, or possibly an `SEH` record, it is noteworthy to mention that it cannot. The reason being, the destination buffer's address resides in the `Heap`, making it significantly distant, especially considering the `0x800` maximum read size constraint.

One last interesting side-note to mention before diving deeper into the rabit hole...

The usage of the `snprintf()` in this scenario is incorrect (obviously on purpose as this is intended to be a vulnerable challenge). Rather than calling `snprintf()` in the following way:

```c
snprintf(buffer, 0x800, quote_string_pointer)
```

`snprintf()` instead should have been called like this:

```c
snprintf(buffer, 0x800, "%s", quote_string_pointer)
```

Also in case you're wondering why `snprintf()` was used (apart from it being part of the vulnerable challenge), instead of a function that's designed to copy strings such as `strcpy()/strncpy()` is most likely because:

1. `snprintf()` will null-terminate the output string automatically. `strncpy()` however will not null terminate the string if the source string is greater than or equal to the number of characters to be copied.
2. 
3. `snprintf()` will not truncate the copy operation if a null byte is encountered in the source string (making this beneficial for an attacker as `0x00` will not be considered a bad character in this specific scenario.

### Write-Primitive Rabbit Hole

While the format string vulnerability can be leveraged to read arbitrary values from the stack, in some rare exceptions it can also be used to write values to memory addresses via the `%n` specifier.

As there are a countless number of resources explaining how this works, it will not be covered in this post. Instead, a rabbit hole involving the write-primitive aspect of the format string vulnerability will be discussed.

After achieving the read-primitive, the next logical step was to test whether a write-primitive would be possible. The majority of modern compilers will disable the `%n` format specifier due to it being considered a security risk thus making the write-primitive an exception rather than the norm.

As such, a quote was written to the database containing the following contents:

```text
w00tw00t%n
```

If successfully evaluated, this will result in the writing the amount of characters before the format specifier (in this case `w00tw00t` is `0x08`) to the argument (which in this case will be the next value on the stack).

After triggering the `get_quote` functionality and stepping through the `snprintf()` call, an `Access Violation` occurs:

```text
(188c.1cf4): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=770a66b0 ebx=0000006e ecx=00000008 edx=00b8028a esi=00b80289 edi=ffffffff
eip=00b77549 esp=025b7180 ebp=025b7228 iopl=0         nv up ei pl nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010216
main!main+0x56c0:
00b77549 8908            mov     dword ptr [eax],ecx  ds:0023:770a66b0=8b55ff8b
```

What's particularly interesting about this exception is that the `ECX` register is attempting to write `0x08` to the contents of a memory address stored in `EAX`.

Does the value of `ECX` look familiar? It should as that's the length of the `w00tw00t` string thus confirming that the `%n` format specifier is not disabled.

The next step would be specific in context of the Operating System the vulnerable application is running in, for example if this was Linux, an entry in the GOT (Global Offset Table) would be overwritten to achieve exploitation. As this application is running on Windows, the next logical step would be to overwrite a return address to instruct the application to jump to the shellcode.

However, a critical problem that is promptly detected is the fact that the arguments passed to the `snprintf()` function are never referenced on the stack. This single fact obstructs the capability to write to any chosen arbitrary memory address. Instead, the ensuing impact will manifest in the form of a denial-of-service (by using the `%n` specifier to instigate an access violation resulting in a crash).

Diving deeper into this issue, when examining the disassembly associated with `snprintf()`; under-the-hood it is discovered that a call `vsnprintf()` is made:

```text
.text:00B72BB0 public _snprintf
.text:00B72BB0 _snprintf proc near
.text:00B72BB0
... args ... 
.text:00B72BB0
.text:00B72BB0 ; __unwind { // 990000
.text:00B72BB0 sub     esp, 1Ch
.text:00B72BB3 lea     eax, [esp+1Ch+arg_C]
.text:00B72BB7 mov     [esp+1Ch+ArgList], eax ; ArgList
.text:00B72BBB mov     eax, [esp+1Ch+Format]
.text:00B72BBF mov     [esp+1Ch+var_14], eax ; Format
.text:00B72BC3 mov     eax, [esp+1Ch+BufferCount]
.text:00B72BC7 mov     [esp+1Ch+var_18], eax ; BufferCount
.text:00B72BCB mov     eax, [esp+1Ch+Buffer]
.text:00B72BCF mov     [esp+1Ch+var_1C], eax ; Buffer
.text:00B72BD2 call    _vsnprintf <------------ here
.text:00B72BD7 add     esp, 1Ch
.text:00B72BDA retn
```

This implies that `snprintf()` essentially behaves as a "wrapper" for `vsnprintf()`, performing preliminary tasks such as setting up the `va_list` type. This practice is common in the implementation of variadic functions in C.

Before going further, let's get familiar with the function prototype for `vsnprintf()`:

```c
int vsnprintf(char *str, size_t size, const char *format, va_list ap);
```

Let's set a breakpoint on the `vsnprintf()` call (aka `main + 0xd49`) and examine the arguments passed to `vsnprintf()` via the stack:

```text
0:003> dds esp L4
01eb70e4  018b3618    // dest
01eb70e8  00000800    // size
01eb70ec  01320280    // format specifier
01eb70f0  01eb7110    // arguments
```

The string format specifier pointer in this case is just referencing a set of `%p` specifiers:

```text
0:003> da 01320280
01320280  "%p %p %p %p %p %p %p %p %p %p %p"
013202a0  " %p %p %p"
```

When examining the arguments pointer (aka `va_list` type), it appears to be an array of `DWORD` values:

```text
0:003> dd 01eb7110
01eb7110  770a66b0 00000385 0131173b 01ebf97c
01eb7120  013118fb 00000001 01eb7944 00004000
01eb7130  00000000 00000000 00000000 00000000
```

Do the values look familiar? They should as these are the values which were pulled from the stack using the read primitive showcased earlier in the post. So what's interesting is that by the time the application reaches the `vsnprintf()` call, the values have already been pulled from the stack.

Furthmore none of the values in the arguments buffer reference the format string specifier like you would typically see. Let's step back to the initial `snprintf()` call (before the subsequent call to `vsnprintf()` is made) and examine the stack at the time of the call:

Displaying `0x100/0n256` entries on the stack shows:

```text
0:003> dds esp L100
022b7680  018b3e30
022b7684  00000800
022b7688  01320280 main!main+0xe3f7
022b768c  770a66b0 msvcrt!_threadstart
022b7690  00000385
022b7694  0131173b main+0x173b
022b7698  022bfef8
022b769c  013118fb main+0x18fb
022b76a0  00000001
022b76a4  022b7ec0
022b76a8  00004000
022b76ac  00000000
022b76b0  00000000
<snipped for brevity all 0x00000000>
022b7a78  00000000
022b7a7c  00000000
```

As shown in the arguments buffer examined in the earlier `vsnprintf()` call, the values from the stack start being copied starting from `0x022b768c` and onwards. Though again what's interesting here is that the format string specifier is no where referenced on the stack. When the `__cdecl` calling convention is used to invoke a function, all the arguments are passed onto the stack thus in the context of format string vulnerabilities, this can be referred to as "writing" a value onto the stack. 

In order to test if this is normal behavior, a simple `C` program was compiled into a `PE32` executable:

```c
#include <stdio.h>

int main() {
	char password[100];
	fgets(password, sizeof(password), stdin);

	char buffer [100];
	snprintf(buffer, 100, password);
}
```

This program basically replicates the same string formatting vulnerability.

Setting a breakpoint on the `snprintf()` call and sending the following input string which will be then treated as a format specifier:

```text
%p %p %p %p %p %p %p %p %p
```

The breakpoint is then invoked and when dumping the values from the stack, the following is revealed:

```text
0:000> dds esp L28
0061fdd0  0061fde8    // dst
0061fdd4  00000064    // size
0061fdd8  0061fe4c    // src
<snipped for brevity>
0061fe4c  25207025
0061fe50  70252070
0061fe54  20702520
0061fe58  25207025
0061fe5c  70252070
0061fe60  20702520
0061fe64  000a7025
0061fe68  ffffffff
0061fe6c  00000030
```

Starting from `0x0061fe4c` and onwards, a pattern is seen and this turns out to the be the format specifier string being referenced on the stack:

```text
0061fe4c  25 70 20 25 70 20 25 70-20 25 70 20 25 70 20 25  %p %p %p %p %p %
0061fe5c  70 20 25 70 20 25 70 20-25 70 0a 00 ff ff ff ff  p %p %p %p......
```

So now the question that's been left to ponder is why in the first example, the format specifiers are not being referenced on the stack thus preventing an attacker from leveraging a write primitive; while in the second case they are being referenced?

### Cracking the Code

In order to answer the question, it helps to review the source code of the vulnerable application which can be found on [Github](https://github.com/bmdyy/quote_db/blob/main/main.c)

Specifically, let's focus on the implementation of the `get_quote()` function:

```c
int get_quote(int index, char **quote)
{
    printf("[?] Getting quote #%d from db...\n", index);
    snprintf(*quote, QUOTE_SIZE, quotes[index]);
    return strlen(quotes[index]);
}
```

As shown above, the function takes two arguments in which the first is an index of type `int` while the second is a double pointer to a `char`.

Upon evaluating the `snprintf()` function invocation, the first argument is obtained by dereferencing the double pointer, yielding a pointer to the `char` that serves as the destination buffer. Following this, `QUOTE_SIZE`, a predefined constant equating to `2048` bytes, is provided as the maximum buffer size. Lastly and arguably the most important, the pointer to the format string specifier (which can be controlled by an attacker) is fetched from the `quotes` array which is a global variable.

Returning back to the test program that was written to test whether the contents of the format string specifier would be referenced on the stack:

```c
#include <stdio.h>

int main() {
	char password[100];
	fgets(password, sizeof(password), stdin);

	char buffer [100];
	snprintf(buffer, 100, password);
}
```

As shown in the earlier section, when sending the contents of `%p %p %p %p %p %p %p`, it would be referenced on the stack:

```text
0:000> dds esp L28
0061fdd0  0061fde8    // dst
0061fdd4  00000064    // size
0061fdd8  0061fe4c    // src
<snipped for brevity>
0061fe4c  25207025
0061fe50  70252070
0061fe54  20702520
0061fe58  25207025
0061fe5c  70252070
0061fe60  20702520
0061fe64  000a7025
0061fe68  ffffffff
0061fe6c  00000030
```

After further review, my initial understanding of how the format string functions worked under-the-hood was wrong.

The reason the contents of the format string specifier are seen on the stack in the second example is because it can be considered "residue" from the earlier `fgets()` call which initially takes the input via `stdin` and stores it in a buffer.

Here's proof of how this behavior works, the first step is to set a breakpoint at the instruction right after the `fgets()` call and examine the stack:

```text
Breakpoint 0 hit
004015fc 8d44247c        lea     eax,[esp+7Ch]

0:000> dds esp L24
<snipped for brevity>
0061fe4c  25207025
0061fe50  70252070
0061fe54  20702520
0061fe58  25207025
0061fe5c  70252070
```

Notice at address `0x0061fe4c` and onwards this contains the input sent to `stdin` aka `%p %p %p %p %p %p %p %p %p`.

Now let's set a breakpoint on the `snprintf()` call and resume execution until the breakpoint is triggered and then re-examine the stack:

```text
Breakpoint 1 hit
004015c2 e8a9ffffff      call    output2+0x1570 (00401570)

0:000> dds esp L30
<snipped for brevity>
0061fe4c  25207025
0061fe50  70252070
0061fe54  20702520
0061fe58  25207025
0061fe5c  70252070
0061fe60  20702520
0061fe64  25207025
0061fe68  70252070
```

Again we notice the "contents" of the format string specifier being referenced on the stack. However upon closer observation of the stack addreses, one will observe that they're the same addresses which were shown after the `fgets()` call. In other words - `snprintf()` never wrote these values to the stack, it was the `fgets()` call! 

Now returning back to the original `QuoteDB` application, let's re-examine how `snprintf()` is invoked one last time:

```c
snprintf(*quote, QUOTE_SIZE, quotes[index]);
```

Specficially `quotes[index]` is of most interest. So the reason in this case we don't see the contents of the format string specifier referenced on the stack (as in the other example) is because the `quotes` array is an array of strings and as it's a global variable, it lives in the `data` segment. Furthermore another pressing reason is because it takes two packets in order to trigger the format string vulnerability:

1. Packet #1 - Add/overwrite quote to contain format string specifier
2. Packet #2 - Invoke get_quote functionality

Each individual packet is handled by a separate thread, so by the time the `get_quote` functionality is triggered, it's entirely in a new thread which has it's own stack!

In summary, the ability to exploit a write primitive in a format string vulnerability depends on the method through which the format specifier is introduced into the respective format string function call.

## Ignoring functionality due to seeing it is only reached when an error happens

During the process of learning how the `QuoteDB` application behaves, it is discovered that is based on the opcode pattern where the packet contains a certain value that will influence how the application will behave next.

When the application receives an opcode, it will then invoke a jumptable which will determine which path to take. In the case where the opcode is invalid (meaning it doesn't meet any of the jumptable cases), it will instead reach the 'default case' which is the following basic block:

```text
.text:01311A85 def_1311862:            ; jumptable 01311862 default case
.text:01311A85 lea     eax, [ebp+buf]
.text:01311A8B add     eax, 4
.text:01311A8E mov     [esp], eax      ; Src
.text:01311A91 call    _log_bad_request
.text:01311A96 mov     eax, [ebp+var_28]
.text:01311A99 mov     [esp], eax      ; Str
.text:01311A9C call    _strlen
.text:01311AA1 mov     [ebp+Size], eax
.text:01311AA4 mov     eax, [ebp+var_28]
.text:01311AA7 mov     [esp], eax      ; Str
.text:01311AAA call    _strlen
.text:01311AAF mov     [esp+8], eax    ; Size
.text:01311AB3 mov     eax, [ebp+var_28]
.text:01311AB6 mov     [esp+4], eax    ; Src
.text:01311ABA lea     eax, [ebp+var_8034]
.text:01311AC0 mov     [esp], eax      ; void *
.text:01311AC3 call    _memcpy
.text:01311AC8 nop
```

As shown by the disassembly above, this basic block invokes a number of functions that deal with string operations and copying memory such as calls to `strlen()` and `memcpy()`.

The one vital mistake I made here was completely ignoring this block due to the presence of the `_log_bad_request()` function which immediately turned off any "hope" for exploitation. After stumbling with the format string write primitive rabbit hole for a couple days, I finally decided to revisit this basic block as it was the only section left which wasn't thoroughly  explored.

Specifically the curiousity was focused on how the `_log_bad_request()` function behaved under-the-hood. Before diving deeper into the disassembly of the function, it is worth examining the arguments passed to the function by examining the stack at the time of the call.

In this case, it's only a single argument and most likely a pointer to a buffer due to the fact that the `LEA` instruction is used to load the address of the argument before it pushed onto the stack.

```text
0:003> dds esp L1
01f66f80  01f6b7ac

0:003> db 01f6b7ac
01f6b7ac  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
01f6b7bc  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
01f6b7cc  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
01f6b7dc  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
```

Our hunches are correct and in this case it turns out to be a pointer referencing our user-input. 

Now let's dive deeper into the disassembly of `_log_bad_request()`:

```text
.text:013116D3 public _log_bad_request
.text:013116D3 _log_bad_request proc near
.text:013116D3
.text:013116D3 var_808= byte ptr -808h
.text:013116D3 Src= dword ptr  8
.text:013116D3
.text:013116D3 ; __unwind {
.text:013116D3 push    ebp
.text:013116D4 mov     ebp, esp
.text:013116D6 sub     esp, 818h
.text:013116DC mov     dword ptr [esp+8], 800h ; Size
.text:013116E4 mov     dword ptr [esp+4], 0 ; Val
.text:013116EC lea     eax, [ebp+var_808]
.text:013116F2 mov     [esp], eax      ; void *
.text:013116F5 call    _memset
.text:013116FA mov     dword ptr [esp+8], 4000h ; Size
.text:01311702 mov     eax, [ebp+Src]
.text:01311705 mov     [esp+4], eax    ; Src
.text:01311709 lea     eax, [ebp+var_808]
.text:0131170F mov     [esp], eax      ; void *
.text:01311712 call    _memcpy
.text:01311717 call    _GetCurrentThreadId@0 ; GetCurrentThreadId()
.text:0131171C mov     edx, eax
.text:0131171E lea     eax, [ebp+var_808]
.text:01311724 mov     [esp+8], eax
.text:01311728 mov     [esp+4], edx
.text:0131172C mov     dword ptr [esp], offset aDInvalidReques ; "....[%d] invalid request=%s\n"
.text:01311733 call    _printf
.text:01311738 nop
.text:01311739 leave
.text:0131173A retn
```

As seen above, this function primarily also appears to deal with operations involving copying memory as denoted by the calls to the `memset()` and `memcpy()` functions making this a potential target for an overflow.

Primarily it appears to be initializing the contents of a memory region to consist of `0x800` null bytes as indicated in the following instructions:

```text
.text:013116DC mov     dword ptr [esp+8], 800h ; Size
.text:013116E4 mov     dword ptr [esp+4], 0 ; Val
.text:013116EC lea     eax, [ebp+var_808]
.text:013116F2 mov     [esp], eax      ; void *
.text:013116F5 call    _memset
```

To maybe get a better understanding, it helps to examine the prototype of the `memset()` function:

```c
void * memset ( void * ptr, int value, size_t num );
```

Using the disassembly above, we can see that the psuedocode would look like the following:

```c
memset(ptr, 0x00, 0x800)
```

Afterwards a `memcpy()` call is invoked, most likely using the memory region which was initalized via the `memset()` call. Let's set a breakpoint and explore the `memcpy()` call in closer detail. Before examining the arguments on the stack, it will be useful to examine the `memcpy()` function prototype:

```c
void * memcpy ( void * destination, const void * source, size_t num );
```

Now it is time to examine the next three values on the stack:

```text
0:003> dds esp L3
01f66760  01f66770    // dst
01f66764  01f6b7ac    // src
01f66768  00004000    // size
```

As the goal of this exercise is to acheive active exploitation via an overflow, the next logical step would be to compare the distance between the address of the destination buffer and the pointers which hold the return addresses. 

However before going further, it is helpful to examine the contents the `source` buffer is referencing and ensure it is values under the attacker's control:

```text
0:003> db 01f6b7ac
01f6b7ac  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
01f6b7bc  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
01f6b7cc  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
```

To discover the pointers which hold the return addresess, the call stack can be viewed:

```text
 # ChildEBP RetAddr  
WARNING: Stack unwind information not available. Following frames may be wrong.
00 01f66f78 01311a96 main+0x1712
01 01f6f7d8 770a6639 main+0x1a96
02 01f6f814 770a6711 msvcrt!_callthreadstart+0x25
03 01f6f81c 76da9564 msvcrt!_threadstart+0x61
04 01f6f830 7773293c KERNEL32!BaseThreadInitThunk+0x24
05 01f6f878 77732910 ntdll!__RtlUserThreadStart+0x2b
06 01f6f888 00000000 ntdll!_RtlUserThreadStart+0x1b
```

The location of the return address for each frame is the address of the frame incremented by `0x04` in other-words, `RET ADDRESS POINTER = ChildEBP + 0x04`

For example, let's take the first frame:

```text
00 01f66f78 01311a96 main+0x1712
```

In this case, `0x01311a96` which is the return address, should be referenced by `0x01f66f78 + 0x04`:

```text
0:003> dds 0x01f66f78 + 0x04 L1
01f66f7c  01311a96 main+0x1a96
```

Afterwards, let's check if that the return address pointer aka `0x01f66f7c` is greater than the address of the destination buffer aka `0x01f66770`:

```text
0:003> ? 0x01f66f7c > 0x01f66770
Evaluate expression: 1 = 00000001
```

As shown by the expression above, it is! This is important because when the memory copy operation is performed it will start writing at `0x01f66770` and onwards (towards higher addresses). If in the case the return address pointer was at a lower address than the destination buffer, it would never be reached as the write operation would happen in the opposite direction.

The final step is to calculate the distance between the return address pointer and the destination buffer:

```text
0:003> ? 0x01f66f7c - 01f66770
Evaluate expression: 2060 = 0000080c
```

As shown in the expression above, the offset is only `0x80c / 0n2060` bytes! This is awfully close and when revisiting the arguments of the `memcpy()` call itself, specifically the `size`, it is `0x4000` which is way more than enough to successfully overwrite the return address pointer. 

So to reiterate the findings, as an attacker is able to control the contents of the values copied from one memory region to another, and the destination region is only `0x80c` bytes below a pointer which references a return address and the attacker has the capability to write `0x4000` bytes, the return address pointer can be overwriten and the attacker can essentially hijack the flow of the application. 

The vital lesson learned here was not to ignore any functionalities of the application **especially** if they deal with memory copy operations.

## Conclusion

While rabbit holes may be frustrating, once figured out, they will most likely yield profound clarity and understanding. It's always better to stumble into a rabbit hole during practice, rather than during the exam. Furthermore by highlighting your mistakes in a postmortem fashion, it will hopefully help prevent those mistakes from being repeated when they count the most.

Thanks for reading.
