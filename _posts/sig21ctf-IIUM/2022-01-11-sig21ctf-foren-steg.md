---
title: Forensics & Steganography Sig21CTF IIUM
date: 2022-01-11
categories: [sig21ctf-IIUM, Forensics]
tags: [forensics, ctf, steg]     # TAG names should always be lowercase
---
## Forensics
### Flag 1.
This challeng we have a png file, but when we try opening it we got an error msg `Invalid filetype`
Inspecting the file we noticed the magic bytes didnt matched a png magic byte.
we need to edit the hex and make it look like this. if we open it again now we should get the flag. `sig21ctfm4g1c_by3s_4r3_0p`

```bash
00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
00000010: 0000 0193 0000 0051 0802 0000 0098 29dc  .......Q......).
00000020: 3d00 0000 0970 4859 7300 000e c400 000e  =....pHYs.......
00000030: c401 952b 0e1b 0000 135a 4944 4154 789c  ...+.....ZIDATx.
00000040: eddc e993 1ce5 7d07 f0e7 e8a7 cf39 f6d4  ......}......9..
00000050: 6ab5 9256 32b2 0e0b 8400 23cc 2dd9 2476  j..V2.....#.-.$v
00000060: b01d 235c c6b8 922a 572a 7995 37f9 6be2  ..#\...*W*y.7.k.
```

## Steganography
### Flag 1.
viewing the begining of the files looks seemingly gebrish, so i paste it to spammic hoping gives something useful. 
`sig21CTF{40d488d2cc8a2319d9d6c70e5c45c358c085216a3d66f86b17c883d0b1cda30e}`

### Flag 2.
For this challenge we have a png file. simply running `steghide extract -sf file.jpg` give us the flag
`sig21CTF{i_bet_you_aint_wearing_your_mask_rn}`

Thanks for reading, I hope this helps :)