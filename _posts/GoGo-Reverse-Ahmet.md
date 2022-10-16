---
layout: post 
title: GoGo Reverse [EN]
date: 2022-10-16 16:45:29 +0300
description: Weird file...?
author: Ahmet Göker
tags: [Binary, Reverse]
---

“What is mathematics? It is only a systematic effort of solving puzzles posed by nature.”
**Shakuntala Devi**

# Topics

<pre>
0x1: Analyze the file
0x2: using ghidra
0x3: gdb-gef
0x4: solving with pwn
0x5: the flag
</pre>

Hello Amazing hackers, welcome back to my blog-post. Today, I found an awesome Re challenge on PicoCTF lets dive into it.




## Analyze the file



First of all, we should analyze the file before doing any stuffs because we need to understand the file itself. When we read the hint, it says you can use objdump or ghidra either.

We will kick off with ghidra but at first:

```
remnux@remnux:~/gogo$ file enter_password 
enter_password: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, Go BuildID=t6eqhYhXAVYpe05Bm9Fu/EX3WrgM8kaGGxtFf0igF/HV3YHofo1wbOBwXOCkYg/YuAJ0i2e2HI1VGjNw_vN, with debug_info, not stripped

```

Awesome. We now understand that its ELF-32 bit. I am going to drop this to ghidra.



## Ghidra

So we can of course use many tools to detect the file, but for now it is great to have to have a knowledge about this weird file. I am going to look at symbol Tree. And I see that:
we have a lot of main functions.

![image](https://user-images.githubusercontent.com/95978207/196054905-ea7c8e0d-e8d2-4490-a8a9-48666203d8ad.png)



The interesting part is: `main.CheckPassWord` this should be checked the password.



```assembly

080d4b30     CMP   AL,BL
080d4b32     XCHG  ESI,EBX


```


We will set a breakpoint at that cmp address. We also ought to not forget that it takes 32 characters.


```c

if(0x1f) < (int)uvar2)
{
	if(ivar3 == 0x20)
		return;
}


```

0x20 == 32.



## gdb-gef


We know the address, and now we are going to set a breakpoint at that address. I have been using `GEF` tool: [gef](https://github.com/hugsy/gef) You can check this out.



We knew it takes 32 characters to bypass the if statement.


```
gef➤  set disassembly-flavor intel
gef➤  break *0x080d4b30
Breakpoint 1 at 0x80d4b30: file /opt/hacksports/shared/staging/gogo_5_8320186217489444/problem_files/enter_password.go, line 71.
gef➤  run
Starting program: /home/remnux/gogo/enter_password 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0xf7ffd000'
[New LWP 3793]
[New LWP 3794]
[New LWP 3795]
Enter Password: 12345678901234567890123456789012
```

In order to read the assembly code more properly, I changed to assembly (intel). I set a breakpoint at `0x080d4b30` and run it. 




```
[#0] 0x80d4b30 → main.checkPassword(input=0x18414300 "12345678901234567890123456789012", ~r1=0xac)
[#1] 0x80d48c2 → main.main()
[#2] 0x806d846 → runtime.main()
[#3] 0x8090a41 → runtime.goexit()
```


We should not forget it runs and cotrols `XOR` thus we need to the find  `$esp` which in this case is `$esp+4` that will be find where it compares.




I am going to dump the hex byte


```
 
 gef➤  hexdump byte $esp+4
0x1843ff28     38 36 31 38 33 36 66 31 33 65 33 64 36 32 37 64    861836f13e3d627d  <--- 
0x1843ff38     66 61 33 37 35 62 64 62 38 33 38 39 32 31 34 65    fa375bdb8389214e  <---
0x1843ff48     4a 53 47 5d 41 45 03 54 5d 02 5a 0a 53 57 45 0d    JSG]AE.T].Z.SWE.
0x1843ff58     05 00 5d 55 54 10 01 0e 41 55 57 4b 45 50 46 01    ..]UT...AUWKEPF.
gef➤  

```
I am going to be able to compare this. We have actually two hexdumps to be compared.


`3836313833366631336533643632376466613337356264623833383932313465` and `3836313833366631336533643632376466613337356264623833383932313465`


I will be using XOR and unhex to get the string but let me use `unhex`


##solving with pwn 

I am going to import everything from `pwn`


```python

from pwn import *
print(unhex("3836313833366631336533643632376466613337356264623833383932313465").decode("utf-8"))
output -> 861836f13e3d627dfa375bdb8389214e

```
Hmm oke... I am going unhex these two bytes with xor...

```python

 print(xor(unhex("3836313833366631336533643632376466613337356264623833383932313465"),unhex("4a53475d414503545d025a0a5357450d05005d555410010e4155574b45504601")).decode("utf-8"))
 output -> reverseengineericanbarelyforward

```
Awesome, we got our string. I am going to try to implement this answer in that bar.



```bash

remnux@remnux:~/gogo$ nc mercury.picoctf.net 48728
Enter Password: reverseengineericanbarelyforward
=========================================
This challenge is interrupted by psociety
What is the unhashed key?

```

hmm. It is asking for unhashed key? We already seen some bytes this means we need to convert to `md5` thus our current string! 
How do I know that because The hash size for the MD5 algorithm is 128 bits.


we need to combine ` 861836f13e3d627d` and `fa375bdb8389214e` together thus --> `861836f13e3d627dfa375bdb8389214e` Lets do that.




## The flag


If we reverse our md5 hash to be string, we will be able to see the word: `goldfish`


Put the answer and grab the flag:  `picoCTF{p1kap1ka_p1c0b187f1db}`







### summary

Thanks for reading this blog. More awesome reverse and malware blogs are coming stay sharp!!!!






Ahmet Göker | Reverse Lover | Math geek | Malware researcher


