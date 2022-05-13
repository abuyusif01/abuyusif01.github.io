---
title: Networking Sig21CTF IIUM
date: 2022-01-11
categories: [sig21ctf-IIUM, Networking]
tags: [networking, ctf, crypto, wireshark]     # TAG names should always be lowercase
---

## Flag 1.
We were given .pcap file, we already know what to do with this file, (open with wireshark)
### Steps
#### 1. 
Filter the traffic to use only http, Should be something like this.
![img](/assets/img/sig21ctf/networking/chall_1.png)
#### 2.
By looking at the traffic i can tell i'm only interested in the post method. So right click at post, then follow `tcp stream` We should have a page like this.
![img](/assets/img/sig21ctf/networking/chall_1_tcp_stream.png)
#### 3.
Extracting the use full data we should have something like this `email=kat2022%40google.com&password=ndb21XOA%7Bnzxpmzykvnnrjmy%7D` urldecoding it will give us this `email=kat2022@google.com&password=ndb21XOA{nzxpmzykvnnrjmy}` Well... still not the exact flag.
#### 4.
After some googling i was able to figure out this is ceaser cipher. so i use this decode-fr to get the final flag
![img](/assets/img/sig21ctf/networking/chall_1_flag.png)

## Flag 2.

### Steps
#### 1.
![img](/assets/img/sig21ctf/networking/chall_2.png)
#### 2.
![img](/assets/img/sig21ctf/networking/chall_2_tcp_stream.png)

#### 3.
For this challenge, all the steps are thesame except for the step 3. we got this `first_name=katnis&last_name=c2lnMjFDVEZ7c2F2ZXRoZWRhdGUwMjAyMjJ9&mobile_no=15062599111&email=kat2022%40google.com&add=true` For this step we don't need to url decode, the text is already in readable format.

```bash
echo "c2lnMjFDVEZ7c2F2ZXRoZWRhdGUwMjAyMjJ9" | base64 -d
sig21CTF{savethedate020222}
```
Thanks for reading, I hope this helps :)