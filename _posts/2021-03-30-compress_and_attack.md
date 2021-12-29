---
layout: post
title:  "Compress and attack - Crypto"
date:   2021-03-30 12:28:05 +0100
categories: writeups
---

```
Challenge: Compress and attack
Author: Shotokhan
Description: Leveraging compression properties to exploit a secure stream cipher
CTF: picoCTF 2021
Category: Crypto
```

# Writeup
We connect to a TCP service and our goal is to find the flag. Source code is provided: <br>
```
#!/usr/bin/python3 -u

import zlib
from random import randint
import os
from Crypto.Cipher import Salsa20

# flag = open("./flag").read()
flag = "picoCTF{Th1s_is_0nly_a_t3St}"


def compress(text):
    return zlib.compress(bytes(text.encode("utf-8")))

def encrypt(plaintext):
    secret = os.urandom(32)
    cipher = Salsa20.new(key=secret)
    return cipher.nonce + cipher.encrypt(plaintext)

def main():
    while True:
        usr_input = input("Enter your text to be encrypted: ")
        compressed_text = compress(flag + usr_input)
        encrypted = encrypt(compressed_text)
        
        nonce = encrypted[:8]
        encrypted_text =  encrypted[8:]
        print(nonce)
        print(encrypted_text)
        print(len(encrypted_text))

if __name__ == '__main__':
    main() 
```
<br> I added the test flag to make some tests offline. <br>
We can see that Salsa20 stream cipher is used; it is a cipher for which there don't exist known vulnerabilites. <br>
The standard way to use that cipher is to concatenate a nonce with the encrypted text, and this is what it's done here. <br>
We have a (partially) chosen plaintext scenario because our input is concatenated to the flag, then it is compressed, and the result of the compression is encrypted. <br>
Now, we couldn't do much if the cipher was a block cipher. <br>
But, since Salsa20 is a *stream* cipher, ciphertext and plaintext have the same length. <br> <br>
Who doesn't have a background about information theory can still search how zlib works, and he or she would see that zlib is based on *entropy encoding*. <br>
Zlib uses an entropy encoding of order > 0, it means that it doesn't computes the entropy on single characters, but on subsequences. <br>
It then creates a variable-length encoding, with short symbols associated to more probable subsequences, and it does something similar to jpeg zig-zag scanning to optimize encoding of repeated symbols. <br> <br>
With that in mind, we can make some tests to validate what we said. We know that flag format is ```picoCTF{...}```, so we know something about the part of the plaintext we can't control. <br>
The idea is the following:

```
"flag" + "uyop" -> compress with zlib -> encrypt with stream cipher -> has a certain length
"flag" + "flag" -> compress with zlib -> encrypt with stream cipher -> is shorter than the previous one
```

Let's test it locally: <br>
<br> ![testing](https://github.com/pwnthenope/pwnthenope.github.io/blob/main/static/post_images/compress_and_attack_tests_for_attack.jpg?raw=true) <br>
Okay, it works, even if only one character changes. <br>
It could still occur that, when only one character changes, the length is the same for two or more different new characters; we will need to handle this situation in the script we're going to implement. <br>
We first tested the script locally, obtaining very good results. <br>
It starts like that: <br>
<br> ![testing](https://github.com/pwnthenope/pwnthenope.github.io/blob/main/static/post_images/compress_and_attack_local_script_start.jpg?raw=true) <br>
Then it goes on, doing a brute-force character-by-character, and then it ends: <br>
<br> ![testing](https://github.com/pwnthenope/pwnthenope.github.io/blob/main/static/post_images/compress_and_attack_local_script_end.jpg?raw=true) <br>
It's very fast locally, but remotely we needed to handle the problem that after a certain timeout the server would close the connection. <br>
The solution is simple: a try-except block with a reconnection logic; the script can then behave like the server never closes the connection. <br>
Here is a snapshot of the script running, handling that situation: <br>
<br> ![testing](https://github.com/pwnthenope/pwnthenope.github.io/blob/main/static/post_images/compress_and_attack_script_running.jpg?raw=true) <br>
And here is the final script: <br>

```
from pwn import *
import string


def get_min_args(zlib_oracle):
    srtd_oracle = sorted(zlib_oracle, key=lambda i: zlib_oracle[i])
    min_value = zlib_oracle[srtd_oracle[0]]
    min_args = []
    for arg in srtd_oracle:
        if zlib_oracle[arg] == min_value:
            min_args.append(arg)
        else:
            break
    return min_args


if __name__ == "__main__":
    # r = process(argv=["python", "compress_and_attack.py"])
    r = remote("mercury.picoctf.net", 50899)
    alphabet = string.ascii_letters + string.digits + "_}"
    base = ["picoCTF{"]
    found = False    
    while not found:
        zlib_oracle = {}
        for partial in base:
            for char in alphabet:
                try:
                    print(r.recvuntil("encrypted: ").decode(), end="")
                    payload = partial + char
                    r.sendline(payload)
                    print(payload)
                    r.recvline()
                    r.recvline()
                    val = int(r.recvline().decode()[:-1])
                    zlib_oracle[payload] = val
                except:
                    # server closes the connection after some time
                    r = remote("mercury.picoctf.net", 50899)
        base = get_min_args(zlib_oracle)
        if len(base) == 1 and base[0][-1] == '}':
            found = True
            r.close()
    print("Flag found: {}".format(base[0]))
```

The script should be self-explainatory, ```zlib_oracle``` is a dictionary with user input as key, and ```len(compress(flag + user_input))``` as value. <br> <br>
picoCTF{sheriff_you_solved_the_crime}
 
