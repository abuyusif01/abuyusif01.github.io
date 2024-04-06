---
title: Crypto & Osint Sig21CTF IIUM
date: 2022-01-14
categories: [sig21ctf-IIUM, Osint]
tags: [Osint, ctf, crypto, RSA, Rotation]     # TAG names should always be lowercase
---
# Crypto
## Flag 1.
![img](/assets/img/sig21ctf/crypto/CRYPTO001.jpeg) <br>
we got an image for this challenge with seemingly gebrish, but cmon the category is cryptography
why not try substitution techniques? `7GEa'!v$L238032J=0D69G80A?20@C06388C2N`
Ok this looks like 47 due to its character composition.
Now lets decode it. I used cyberchef for that.
And heres the flag.
![img](/assets/img/sig21ctf/crypto/flag_1_answer.png)

## Flag 2.

We got a file with the folling content
```bash
n = 47871871319309860974932493994368503837616324093829993047813212088563420860561
c = 18061800228431074448341444333709757167868575268631469201579336930973186970176
e = 6553
```
So i wrote a simple python script to break this

```python
from Crypto.Util.number import *
from factordb.factordb import FactorDB

c = 18061800228431074448341444333709757167868575268631469201579336930973186970176
n = 47871871319309860974932493994368503837616324093829993047813212088563420860561
e = 65537

# init factordb connection
f = FactorDB((n))
f.get_factor_list()
f.connect()

# store res in result
result = f.get_factor_list()

p = result[0]
q = result[1]
phi = (p-1) * (q-1)
d = inverse(e, phi)
m = pow (c, d, n)
print(long_to_bytes(m))

```
And we got the flag. `sig21CTF{crypt0_rs4_t00_3asy}`

## Flag 3.

We got 2 file. message.secret and key.pub

```
message.secret content
HELLO!!!!!!.... I HEARD YOU WERE LEARNING SOME CRYPTOGRPHIC TRICKS..
CAN YOU GET THE FLAG..... I RECIEVED THIS MESSAGE BUT I CANT FIGURE IT OUT..
THEY ALSO LEFT THIS HINT `dGhpcyBtaWdodCB0YWtlIGEgd2hpbGUuLi4uIHNvIGRvbnQgZ2l2ZSB1cC4uIHdlIHVzZWQgdGhlIHVzdWFsIHZhbHVlIGZvciBl`

c = 36471761181664780564914260343964863418853945528543016847566551168186484704567

```
I decode the hint to `this might take a while.... so dont give up.. we used the usual value for e`

```
key.pub content
-----BEGIN PUBLIC KEY-----
MDswDQYJKoZIhvcNAQEBBQADKgAwJwIgYoP1rrW69NmQ8LzNsTX6ongx3kS4IxCh
TlY1JynxjJUCAwEAAQ==
-----END PUBLIC KEY-----
```
From the hint we know its RSA, so we basically need to find p, q, phi, d, c, n
but how can get n when its not give? the answer here is using rsaCTFtools to get n from .pub file,
`RsaCtfTool.py --dumpkey --key key.pub`
Now we got n and e

```
n = 44559811764670192392592515903341200648507091942717623043713990581324912626837
e = 65537
c = 36471761181664780564914260343964863418853945528543016847566551168186484704567
```
Now the only thing left is getting p, q. Let use our previous script to get it

```python

from Crypto.Util.number import *
from factordb.factordb import FactorDB
n = 44559811764670192392592515903341200648507091942717623043713990581324912626837
e = 65537
c = 36471761181664780564914260343964863418853945528543016847566551168186484704567
f = FactorDB((n))
f.get_factor_list()
f.connect()

result = f.get_factor_list()

p = result[0]
q = result[1]
phi = (p-1) * (q-1)
d = inverse(e, phi)
m = pow (c, d, n)

print(long_to_bytes(m))

```
But hey.. why is the flag printing this `7\xec\x83\x98\x0c\x96\x7f%\x04\x07V".\x91\x83z\xea\xce\xf8\xb4\x805c\x86\xaf\x1c@\xfb0\xa5q\xf5` ?
Well.. i made a mistake encrypting the wrong massage c. And i deeply apologize to the participants that spend hours trying to solve this challenge.
Anyways u got the steps on how to solve this kinda challenges.

# Osint
Link to the write up
[gdrive](https://docs.google.com/document/d/1nVO-ep5SXDoAIvMN3LYxDb-HLVTEJx2_BfFClBXuZzc/edit)

Thanks for reading and i hope this helps :)
