---
layout: post
title:  "Frown (and revenge) - Reverse"
date:   2024-01-21 12:28:05 +0100
categories: writeups
--- 

```
Challenge: frown & frown-revenge
Authors: Shotokhan
Description: Reversing through Frida and guessing encryption properties
CTF: Insomnihack teaser 2024
Category: Reverse
```

## frown
> How good is your Tetris? Connect, win, and reveal the flag!

> `ssh user@frown.insomnihack.ch -p24`

> password: 1nsomn1h4cker

The game is a tetris. After a few lines completed, it says that a socket is listening on localhost on port 27042.

![screen_frown.png](https://github.com/pwnthenope/pwnthenope.github.io/blob/main/static/post_images/screen_frown.png?raw=true)

I managed to connect to that port using SSH local port forwarding: `ssh -L 127.0.0.1:27042:127.0.0.1:27042 user@frown.insomnihack.ch -p24`.

I discover that there is a HTTP server on that port, but any page I try returns a 404 error.

In fact, it's a *Frida* server, so I have to connect to it using `frida` client.

For example: 

```
$ frida-ps -H 127.0.0.1
PID  Name
--  ------
18  Gadget
```

```
$ frida -H 127.0.0.1 Gadget
    / _  |   Frida 16.1.11 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to 127.0.0.1 (id=socket@127.0.0.1)
                                                                                
[Remote::Gadget ]-> Process.enumerateModules()
[
    {
        "base": "0x564e13b9b000",
        "name": "tetris",
        "path": "/usr/local/bin/tetris",
        "size": 29920
    },
    ...
]

[Remote::Gadget ]-> console.log(hexdump(Memory.readByteArray(ptr(0x564e13b9b000), 29920), { offset: 0, length: 29920, header: true, ansi: true }));
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00  .ELF............
00000010  03 00 3e 00 01 00 00 00 d0 14 00 00 00 00 00 00  ..>.............
00000020  40 00 00 00 00 00 00 00 88 62 00 00 00 00 00 00  @........b......
00000030  00 00 00 00 40 00 38 00 0d 00 40 00 1e 00 1d 00  ....@.8...@.....
00000040  06 00 00 00 04 00 00 00 40 00 00 00 00 00 00 00  ........@.......
00000050  40 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  @.......@.......
00000060  d8 02 00 00 00 00 00 00 d8 02 00 00 00 00 00 00  ................
...
```

The previous command was for obtaining an hexdump of the whole `tetris` binary, in order to be able to inspect it. I convert the hexdump to base64 using cyberchef, then I decode it to file.

```
$ file tetris 
tetris: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

By looking at some decompiled code:

```C
      lVar6 = dlopen("libttyris.so",2);
      if (lVar6 == 0) {
        uStack272 = 0x102ea6;
        puVar4 = (undefined *)dlerror();
        pcVar8 = " [flag] not found %s";
      }
      else {
        uStack272 = 0x102e3e;
        pcVar3 = (code *)dlsym(lVar6,"flag_key");
        uStack272 = 0x102e4b;
        local_100 = (undefined4 *)malloc(100);
        lVar7 = 0x19;
        puVar10 = local_100;
        while (lVar7 != 0) {
          lVar7 = lVar7 + -1;
          *puVar10 = 0;
          puVar10 = puVar10 + (ulong)bVar11 * -2 + 1;
        }
        uStack272 = 0x102e70;
        (*pcVar3)(param_9[0x20],local_100,100);
        puVar4 = local_ec;
        uStack272 = 0x102e7f;
        dlclose(lVar6);
        uStack272 = 0x102e95;
        FUN_00101d2f("http://frown-service/",local_100,puVar4);
        pcVar8 = " [flag] %s";
```

It looks like the binary reads "flag key" as an exported symbol, with symbol name `flag_key`, from a shared object called `libttyris.so`. Then, it sends it to `http://frown-service/`, in function `FUN_00101d2f` (using `curl` API).

So, I perform local port forwarding again, to access that endpoint: `ssh -L 127.0.0.1:9000:frown-service:80 user@frown.insomnihack.ch -p24`.

Trying to perform a *GET*:

```
$ curl -X GET 127.0.0.1:9000
only posts please
```

Let's try a *POST* then:

```
$ curl -X POST 127.0.0.1:9000
key too short
```

Increasing the input length:

```
$ curl -X POST --data "flag_key=01234567890123456789012" 127.0.0.1:9000
(=!j1>lb42Wnv7=f#`=m>h)
```

From decompiled code, it's possible to see that what's returned from this endpoint is used in the format string `" [flag] %s"`, so it must be the flag itself. As such, the `flag_key` symbol is the key to decrypt the flag. The minimum length needed is 23 (also, more than 23 does not change the output). The output length is 31.

By playing with this, I discover that the characters of the input `flag_key` are used to XOR. I verified by providing an input of all characters `0`, an input of all characters `1`, and by verifying that:

- Be `s_0` the output obtained with all characters `0`, be `s_1` the output obtained with all characters `1`.
- `s_0[:9] == s_1[:9]`: the first 9 characters of the output are always the same.
- `xor(xor(s_0[9:], '0' * 22), '1' * 22) == s_1[9:]`.

So, with `xor(s_0[9:], '0' * 22)` I obtain the original bytes:

```
'\x19\x17\x03(\x15=!\x1ej\x01\x0f\x11;XW\x02\x05oWF\x06\x0f<R\x16V\nU\x07X\x18'
```

Now the last thing is understanding how to get the flag from these bytes.

The flag seems to be xored, so we need the xor key. Back to frida, we first try to scan memory. But the stack was probably overwritten by program execution.

We then try to load the library used to get the flag key:

```
[Remote::Gadget ]-> Module.load('libttyris.so')
{
    "base": "0x7f7bf43a7000",
    "name": "libttyris.so",
    "path": "/usr/lib/libttyris.so",
    "size": 16408
}

[Remote::Gadget ]-> Process.enumerateModules()[38].enumerateExports()
[
    {
        "address": "0x7f7bf43a810f",
        "name": "flag_key",
        "type": "function"
    },
    {
        "address": "0x7f7bf43a8109",
        "name": "flag_size",
        "type": "function"
    }
]

```

I then dump the library with the same technique used to dump the binary, in order to be able to open it in Ghidra.

The next step could be either to setup the binary such to debug it, or to write a program that calls `flag_key` function.

Before doing that, I take a step back by looking again at how the binary performs the curl request to the `frown-service` endpoint. Actually, I managed to understand why in my case the first 9 bytes were always the same: because the POST request does not want parameters, it just accepts a body of at least 31 bytes and use them to XOR with the flag. In my case, then, I was using `flag_key=` as xor key. The "correct" encrypted flag is:

```
\x7f\x7b\x62\x4f\x4a\x56\x44\x67\x57\x01\x0f\x11\x3b\x58\x57\x02\x05\x6f\x57\x46\x06\x0f\x3c\x52\x16\x56\x0a\x55\x07\x58\x18
```

I then wrote a custom program to decrypt the flag, calling the `flag_key` function with parameters similar to the reversed `tetris` binary. The first parameter of the function depends on the timestamp at which the binary is executed, but is constrained to be greater than `0xffffdc80` (by the code) and maximum `0xffffffff` (because it's a 4 byte integer). Here's the program:

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>


void print_hex_until_null(const char *buffer) {
    for (int i = 0; buffer[i] != '\0'; ++i) {
        printf("%02X ", (unsigned char)buffer[i]);
    }
    printf("\n");
}

void xor(char* a1, char* a2, char* out, unsigned int size) {
    for (unsigned int i=0; i<size; i++) {
        out[i] = a1[i] ^ a2[i];
    }
}

int main() {
    char enc_flag[] = "\x7f\x7b\x62\x4f\x4a\x56\x44\x67\x57\x01\x0f\x11\x3b\x58\x57\x02\x05\x6f\x57\x46\x06\x0f\x3c\x52\x16\x56\x0a\x55\x07\x58\x18";
    char dec_flag[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    const char* target = "INS{";
    void* libttyris = dlopen("./libttyris.so", 2);
    if (libttyris == NULL) {
        printf("Error opening library\n");
        exit(1);
    }
    void* flag_key_func = dlsym(libttyris, "flag_key");
    char* flag_key = malloc(100);
    if (flag_key == NULL) {
        printf("Malloc error\n");
        exit(1);
    }
    memset(flag_key, 0, 100);
    int param = 0xffffdc80;
    // int param = 0;
    while (param < 0xffffffff) {
        ((void(*)(int, void*, unsigned int))flag_key_func)(param, flag_key, 100);
        xor(flag_key, enc_flag, dec_flag, 31);
        // print_hex_until_null(flag_key);
        if (strstr(dec_flag, target) != NULL) {
            printf("%s\n", dec_flag);
            break;
        }
        memset(dec_flag, 0, 32);
        memset(flag_key, 0, 100);
        param += 1;
    }
    return 0;
}
```

And this is the `Makefile`:

```
all:
	gcc -ldl call_flag_key.c -o call_flag_key

clean:
	rm -f call_flag_key
```

Execution of the program:

```
$ ./call_flag_key 
INS{y0u_c4nt_h1d3_fr0m_fr333da}
```

## frown-revenge
The second version of the challenge.

> How REALLY good is your Tetris? Connect, win, and reveal the flag!

> `ssh user@frown-revenge.insomnihack.ch -p24`

> password: 1nsomn1h4cker

By playing tetris again, it's possible to see that *frida* is still there.

In fact I started the connection with both the local port forwardings:

```
$ ssh -L 127.0.0.1:27042:127.0.0.1:27042 -L 127.0.0.1:9000:frown-service:80 user@frown-revenge.insomnihack.ch -p24
```

In frida, I can guess that the binary is very similar to the previous one:

```
[Remote::Gadget ]-> Process.enumerateModules()
[
    {
        "base": "0x5603ec01c000",
        "name": "tetris",
        "path": "/usr/local/bin/tetris",
        "size": 29920
    },
...
]
```

Because it has the same path and the same size. Also, if I do `Module.load('libttyris.so')`, that module has same path and size too. I don't know what changes so far, maybe I already found the hardest solution without discovering some vulnerability in the previous version.

By interacting with `frown-service`, I quickly learn that key length is 32 (again), but this time the output size is 55. Chance is that the key is used cyclically.

After verifying that the key is used cyclically, I wrote down the encrypted flag:

```
\x2c\x7a\x32\x19\x02\x00\x45\x17\x4c\x69\x4b\x56\x65\x67\x46\x17\x1d\x3c\x73\x2d\x7d\x3b\x0c\x5a\x5c\x06\x3b\x70\x58\x25\x6a\x10\x55\x59\x52\x16\x55\x5c\x04\x17\x67\x6f\x5d\x4c\x6f\x79\x60\x20\x3b\x0f\x47\x00\x52\x1d\x19
```

And I try to use the previous C program again, with little modifications. At first the program did not work, so I dumped the new tetris binary. I saw that this condition:

```C
    if (param_9[0x20] != DAT_00107144 && (int)DAT_00107144 <= (int)param_9[0x20]) {
      uStack272 = 0x102e27;
      lVar5 = dlopen("libttyris.so",2);
```

Which regulates the first parameter to the `flag_key` function, this time is different, i.e., the value of `DAT_00107144` is much smaller. Also, by dumping the `libttyris.so` shared object for the new challenge, it looks like it has some differences as well.

Even if changing the script accordingly, I wasn't able to decrypt the flag.

By looking at decompiled code, I notice the following:

```C
    if ((((local_ec != 'I') || (local_eb != 'N')) || (local_ea != 'S')) || (local_e9 != '{')) {
        pcVar7 = "incorrect flag";
    }
```

It looks like there is some reason why in some cases the flag would not be correct. So I try to make the first parameter to the `flag_key` function span the whole space of integers, i.e., make it start from 0. That eventually worked to get the flag, with the following script:

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>


void xor(char* a, char* k, char* out, unsigned int size, unsigned int key_len) {
    for (unsigned int i=0; i<size; i++) {
        out[i] = a[i] ^ k[i % key_len];
    }
}

int main() {
    char enc_flag[] = "\x2c\x7a\x32\x19\x02\x00\x45\x17\x4c\x69\x4b\x56\x65\x67\x46\x17\x1d\x3c\x73\x2d\x7d\x3b\x0c\x5a\x5c\x06\x3b\x70\x58\x25\x6a\x10\x55\x59\x52\x16\x55\x5c\x04\x17\x67\x6f\x5d\x4c\x6f\x79\x60\x20\x3b\x0f\x47\x00\x52\x1d\x19";
    char dec_flag[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    const char* target = "INS{";
    void* libttyris = dlopen("./revenge_libttyris.so", 2);
    if (libttyris == NULL) {
        printf("Error opening library\n");
        exit(1);
    }
    void* flag_key_func = dlsym(libttyris, "flag_key");
    char* flag_key = malloc(100);
    if (flag_key == NULL) {
        printf("Malloc error\n");
        exit(1);
    }
    memset(flag_key, 0, 100);
    // int param = 0x080e4110;
    int param = 0;
    while (param < 0xffffffff) {
        ((void(*)(int, void*, unsigned int))flag_key_func)(param, flag_key, 100);
        xor(enc_flag, flag_key, dec_flag, 55, 32);
        if (strstr(dec_flag, target) != NULL) {
            printf("%s\n", dec_flag);
            break;
        }
        memset(dec_flag, 0, 56);
        memset(flag_key, 0, 100);
        param += 1;
    }
    return 0;
}

```

Script execution:

```
$ ./revenge_call_flag_key 
INS{f1rst_yoU_try_AND_hide_AnD_s0m3t1m3s_You_ARE_lucky}

```

