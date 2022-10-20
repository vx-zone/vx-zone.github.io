---
layout: post
title: Kaspersky-AV Engine
date: 2022-09-20 13:58:02 +0300
description: Understanding AV
author: Ahmet Göker
comments: true
tags: [Malware Analysis, Forensics, EN]
---


_“I was addicted to hacking, more for the intellectual challenge, the curiosity, the seduction of adventure; not for stealing, or causing damage or writing computer viruses.”_
-- **Kevin Mitnick**


**_Greetings to the best hackers in the world. Today I am going to illustrate How Kaspersky-AV's mechanism works. Let's get started_**

# Table Of Contents
<pre>
1. AV Software Evasion
	1x1 Malware and Detection
	1x2 Binary Instrumentation and Taint Analysis
2. AV static Detection
	2x1 Static Evasion Detection Technique
	2x2 Create own signature Database
	2x3 Yara rules for static detection
3. Kaspersky-AV - RE Analysis with DnSpy
	3x1 Kaspersky-AV scan Engine
	3x2 Code base Analysis
</pre>

I will also use signature-evasion room from Tryhackme to explain and demonstrate it understandably.



# AV Software Evasion
This topic is one of my favorite topics which I have written before. Today, İ will be covering about AV and kaspersky scan engine.
You might not know about AV software evasion but this topic will be really interested and handy to malware writers, penetration testers, and vulnerabilty researchers.
This reason of that is; this ensures the payload which every hacker wants to execute in the target machine or not being blocked by AV machine.
Evasion technique or in other words (AV bypassing) can be divided in two categories: static and dynamic. Let me first explain what ```static``` does.
```Static``` should be considered as, that you want to simply want to bypass detection based on the AV's signature algorithms.
Let me now explain a little bit about ```dynamic```. Dynamic shoud be considered as, that you want to bypass detection of the behaviour when it AV is executed. This will be huge topic but let me try to explain understandably for beginners friendly.
Have you ever heard about (CRC) which stands for ```cyclic rendundancy check algorithm```. With some technique such as fuzzing, hashing technique you are able to change the structure or in the words the graph of the program. Being able to make it meaningful with this statement,it will be altering 
the binary contents and also can be tricked into believing the program is different nor malicious. In order to enhance your skills you can research and try to change the graph of the program
to evade AV into sandbox or emulator.

You can use a plethora of different technique to bypass such AV. I will also explain and demonstrate bypassing AV.
Now lets move forward to ```Malware and Detection```


## Cyclic redundancy check 
A cyclic rendundancy check is an error-detecting-code commonly used in digital network
and storage devices to detect accidental changes to digital data.Blocks of data entering these systems get a short check value attached, based on the remainder of a polynomial division of their contents.

You can get more information from: [CRC](https://en.wikipedia.org/wiki/Cyclic_redundancy_check


# Malware and Detection

In order to have a better understanding about AV evasions, this will be the right place to sit and read.
The key part of AV evasion is also determining and considering malware's behaviour as well as the detection.
For instance, a specific sample through static or whether dynamic that some signature, or is detected through malcious's behaviour.
But why? is it detected because of specific signature or based on the functions by a (PE) which stands for ```Portable Executable```
We can also check the entropy of a code or data section but is it also possible by catching strange and suspicious strings ? Yes of course.
Malware authors/writers had a great technique to bypass av. It is an old technique which we call ```Divide and Conquer```
We should understand that without math you will not be able to work with:)

Let me explain about this technique. lets consider we have a file but you are willing to bypass the AV right?
We will need to split the file into smaller parts and each one should be analyzed all those binary separetly. The reason why we need to analyze such binary is that
we are willing to evade of that part from AV where you are targeting. We ought to concern on this technique carefully, because it works fine with checksum-based signature
or pattern matching. If we are going to split our malicious PE file into half, it is important that AV kernel
will surely check of our is executable (PE) because when you are splitting your file, it can be that PE will no longer be valid. Which means that there is no longer executable file
and in that case will not be detected.

The file's offset starts 0 to 256 byte and the next file contains from 0 to 512 and so on....
This technique can be very handy thus you should be alerted while doing your research by this.


Changing anything from that file will occur be changing the hash. Most malware researchers check the ```MD5``` checksum.
You just only would change a single bit from that file and hash shall be changed.


Let me write a simple python script, which divides my file into smaller part.


```python

class file:
	def __init__(self,filename):
		self.b = open(filename, "rb")
		self.block_size = 256
		
		
	def split(self, path):
		blocks = len(self.b) / self.block_size
		for x in range(1, blocks):
			buf = self.b[:x*self.block_size]
			way = os.path.join(path, "block_%d",x)
```



```

C:\Users\Student\Desktop\Tools>ThreatCheck.exe -f C:\Users\Student\Desktop\Binaries\shell.exe
[+] Target file size: 73802 bytes
[+] Analyzing...
[*] Testing 36901 bytes
[*] No threat found, increasing size
[*] Testing 55351 bytes
[*] Threat found, splitting
[*] Testing 52612 bytes
[*] Threat found, splitting
[*] Testing 51098 bytes
[*] Threat found, splitting
[*] Testing 50341 bytes
[*] No threat found, increasing size
[*] Testing 62071 bytes
[*] Threat found, splitting
[*] Testing 56206 bytes
[*] Threat found, splitting
[*] Testing 53273 bytes

```


	

In order to test it by yourself, you can use ```clamscan``` which can be downloaded in Linux OS.

## Important !

Please, when you create a malware with being packed you should be aware that such open-source tools are always
distributed with antivirus products, whether they are open-source tools or not. the main difference is that
unpackers for the signature are not distributed by the antivirus. You can check  always which AV products are not contributed.
You can always use your own bypass, obfuscation, packer technique to be bypass AV.

**When you discover a pattern in hex that maches visibility:hidden sub string, it would be easier to evade detection when you use plain-text signature**



 
# Binary Instrumentation and Taint Analysis
For people who are interested in analyzing binary you can check this book [binary-analysis](https://www.amazon.com/Practical-Binary-Analysis-Instrumentation-Disassembly/dp/1593279124)
Let me explain a bit what ```binary instrumentation```. Binary instrumentation, if already can hear from this term, that has been the ability to monitor assembly instruction level. Everthing was it is doing 
behind the scenes, will ```taint-analysis``` be tracked and discovered the flow of data, after the reading the instructions such as ```recv```. This analysis will be influencing
the code flow. Of course, we have open-source tool and a downloadable resource for this to perfom such analysis.
As i would give an example; intel-pin and the open-source ```DynamoRIO``` such tools can be performed/instrumented such binary analysis.
When there are malware's bytes to be implemented into that file, tools which I mentioned will be able to instrument binaries to catch them 
You can always play around with such tools, and consider that you may be tempted to make your ```taint analysis``` more complex. How data flows be detected until its being detected.



**Important** 

You should not forget that this approach is discouraged because:

1. You want to scan a file and your throw that to AV however, do not forget that not all AV behaves its same.
Your file can be opened many times to be analyzed. It totally depends the number of different engines that the antivirus uses.

2. This might also give some issue when your file is opened in AV and be read only once, thus all bytes in the file are instrumented
(tained), you should trace the numbers to have to have filter out(huge gigabytes).

3. You should also not forget that bypassing static signature is extremely easy because:
you can write a complex such a system, and even in suppositional situation where most cases can be worked, and also most problems can be fixed

check this out: [intel-pin](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-dynamic-binary-instrumentation-tool.html)
check this out: [DynamoRIO](https://dynamorio.org/)


### Summary
We understood from the first part that AV can be bypassed and how it works.
AV software evasion techniques are not only researched by malware writers but also by 
penetration testers because they are the people who are hired by companies to test their infrastructures thus such testers
need to be able to bypass the deployed AV products.

- ```Static``` evasion will also be used by threat actors because this technique will help them to modify the content, and checksums,hashes will be changed.
When this work runs properly, AV will not be able to detect because of signature-based detections.

- We also already mentioned about ```the divide and conquer``` technique, which can be split the malicious file
in chunks and then scan each chunk separetly to identify the chunk in that file.

- ```binary instrumentation``` and ```taint analysis``` can be very handy, with libraries as intel-pin and the open-source 
framework called ```DynamoRıo```, can be used to track the execution of the AV.



Now I am going to analyze and bypass AV checks. Let's get started.



# Static Evasion Detection Technique
We already know that when we use static evasion technique that being achieved by modifying
the content as well as the input file so its hash or checksum is changed, and that AV will not be able to detect
using signature-based detections.

Now in this part of my blog, i am going to bypass AV by using bypass technique. I found an awesome room on tryhackme about AV that I will walkthrough.

If you are ready let me illustrate what we have learned briefly.


## Static Evasion
Now to make it more efficient of my blog, i decided to demonstrate how static evasion detection works. In order to complete this challenge let me cover briefly what we have learned.
If we are generally speaking about AV detection which can be classified into three main approaches:

1. Static Detection
2. Dynamic Detection
3. Heuristic and Behavioral Detection

In this part we will concern on `static Detection` technique, which is the simplest type AV detection. This technique is based on signature, hashes, CRC, sequence of bytecodes.
We can simply think about comparisons between existing file which is already in the operating system. When this file has been detected or considered through signature then, can be considered as malicious file.


I will put an image where you will be able to understand static engine better.

Now, in this challenge we are going to be using `signature-based detection` technique to see how AV behaves and how such products detect malware files.
You can not easily bypass AV with this technique and it only works by know malicious files. With this statement which should understand that
signature database should be updated from time to time because if not, the chance is that threat authors can bypass this.

In this part we will be using `ClamAV` tool to illustrate how signature behaves as well as identifying malicious files.

Now lets kick off. I am going to use this room on THM [Intro-AV](https://tryhackme.com/room/introtoav)



To start off, we have couple of malware samples to be used.

You can get more information about `clamscan.exe` [info](https://linux.die.net/man/1/clamscan)


It is important to constantly update our database because as i mentioned, most threat actors might be able to bypass it.


```

c:\>"c:\Program Files\ClamAV\clamscan.exe" c:\Users\thm\Desktop\Samples
Loading:    22s, ETA:   0s [========================>]    8.61M/8.61M sigs
Compiling:   4s, ETA:   0s [========================>]       41/41 tasks

C:\Users\thm\Desktop\Samples\AV-Check.exe: OK
C:\Users\thm\Desktop\Samples\backdoor1.exe: Win.Malware.Swrort-9872015-0 FOUND
C:\Users\thm\Desktop\Samples\backdoor2.exe: OK
C:\Users\thm\Desktop\Samples\eicar.com: Win.Test.EICAR_HDB-1 FOUND
C:\Users\thm\Desktop\Samples\notes.txt: OK
`
```

Let me explain a bit about this result.

There are 5 files, these are:

1. EICAR
2. backdoor-1
3. backdoor-2
4. AV-check 
5. notes.txt

We know that `notes.txt , AV-Checker,` are not malicious but what about `backdoor-2.exe` hmm interesting is it not?

`ClamAV` offers us to use --debug command to see what kind of modulus being loaded during the scanning process


We are going to look closer at `backdoor-2.exe`


```
LibClamAV debug: Checking realpath of C:\Users\thm\Desktop\Samples\backdoor2.exe
LibClamAV debug: cli_get_filepath_from_handle: File path for handle 00000000000005A0 is: C:\Users\thm\Desktop\Samples\backdoor2.exe
LibClamAV debug: Recognized MS-EXE/DLL file
LibClamAV debug: cache_check: 75047189991b1d119fdb477fef333ceb is negative
LibClamAV debug: cli_peheader: SizeOfHeader is not aligned to the SectionAlignment


```

and `backdoor-1.exe`


```
LibClamAV debug: FP SIGNATURE: 1df33052eaaa5d577a6287856c8ed7a7:6144:Win.Malware.Swrort-9872015-0  # Name: backdoor1.exe, Type: CL_TYPE_MSEXE
C:\Users\thm\Desktop\Samples\backdoor1.exe: Win.Malware.Swrort-9872015-0 FOUND
LibClamAV debug: hashtab: Freeing hashset, elements: 11, capacity: 64

```


When we compare these two files. We see that backdoor-1 was detected because of predefined malicious sequence of bytecode values. So, that means `clamscan` was able to detect.


Hmm interesting, `backdoor-2.exe` could not be detected by clamscan because of `xor` encryption shellcode

thus it means that, clamscan could not find into database.



`EICAR` was detected by detected by clamscan because of md5 checksum. Let me use debug mode 



```
LibClamAV debug: FP SIGNATURE: 44d88612fea8a8f36de82e1278abb02f:68:Win.Test.EICAR_HDB-1  # Name: eicar.com, Type: CL_TYPE_TEXT_ASCII

```
To check whether the checksum is correct or not, let me use `sigtool.exe` 

```
c:\>"c:\Program Files\ClamAV\sigtool.exe" --md5 c:\Users\thm\Desktop\Samples\eicar.com
44d88612fea8a8f36de82e1278abb02f:68:eicar.com
```

And yes, it is correct.


Now lets move forward to create our signature database.

## Create own signature Database
We already know that, clamscan could not unfortunately find that `backdoor-2.exe` was malicious however, we should not worry about it.
We are going to implement the checksum to AV(clamscan) which has been missed. 

The first part is easy. We will be able to create an MD5 signature for the file, and the second, we will be able to add the generated
signature into a database with the extension `.hdb`
The last part, we will be going to rescan against the file whether it scans as malicious or not.

**1**
```
C:\Users\thm\Desktop\Samples>"c:\Program Files\ClamAV\sigtool.exe" --md5 backdoor2.exe
75047189991b1d119fdb477fef333ceb:6144:backdoor2.exe 
```
**2**
Now that we know MD5, we are going to create our own database:
```
C:\Users\thm\Desktop\Samples>"c:\Program Files\ClamAV\sigtool.exe" --md5 backdoor2.exe > thm.hdb

```
**3**

Clamscan could not check that `backdoor-2.exe` was malicios or not. Now we will add the generated md5 to our database
with filename called `thm.hdb`


```
:\Users\thm\Desktop\Samples>"c:\Program Files\ClamAV\clamscan.exe" -d thm.hdb backdoor2.exe
Loading:     0s, ETA:   0s [========================>]        1/1 sigs
Compiling:   0s, ETA:   0s [========================>]       10/10 tasks

C:\Users\thm\Desktop\Samples\backdoor2.exe: backdoor2.exe.UNOFFICIAL FOUND

```

When we try to rescan this file with Clamscan,we see that `backdoor-2.exe` was detected as malicios, because the file's checksum has the same signatuıre what its into the database


## Yara rules for static Detection

 We can also use yara rules in our static detection process. Yara is a tool which allows malware analyst to identify and detect malware.
 In order to use rule-based detection we can get help from Yara with this tool we are able to create new rule to make it our detectetion process sophisticated.
 
 Now, we are going to analyze the malware with help of Yara rule.
 
 
 As an example, we will use AV-Checker to write a rule for it.
 
 First of all, we will analyze the file with string tools. With string tools, we can see
 all functions, variables, and nonsense strings. We should not forget that we can also find useful and meaningful strings
 
 AV-Checker uses a program database called (.pdb) which is a symbolic debugging information.
 
 
 ```
C:\Users\thm\Desktop\Samples>strings AV-Check.exe | findstr pdb
C:\Users\thm\source\repos\AV-Check\AV-Check\obj\Debug\AV-Check.pdb
 ```

for more information about Yara we can check this out --> [Yara](https://github.com/Yara-Rules/rules)


We will use this Yara rule:



```
rule thm_demo_rule {
	meta:
		author = "THM: Intro-to-AV-Room"
		description = "Look at how the Yara rule works with ClamAV"
	strings:
		$a = "C:\\Users\\thm\\source\\repos\\AV-Check\\AV-Check\\obj\\Debug\\AV-Check.pdb"
	condition:
		$a
}


```

I am not going to explain step by step what it does but let me explain briefly about the next process.

We should store this rule with .yara extension that clamscan can deal with. We are going to rescan this against

```
C:\Users\thm>"c:\Program Files\ClamAV\clamscan.exe" -d Desktop\Files\thm-demo-1.yara Desktop\Samples
Loading:     0s, ETA:   0s [========================>]        1/1 sigs
Compiling:   0s, ETA:   0s [========================>]       40/40 tasks

C:\Users\thm\Desktop\Samples\AV-Check.exe: YARA.thm_demo_rule.UNOFFICIAL FOUND
C:\Users\thm\Desktop\Samples\backdoor1.exe: OK
C:\Users\thm\Desktop\Samples\backdoor2.exe: OK
C:\Users\thm\Desktop\Samples\eicar.com: OK
C:\Users\thm\Desktop\Samples\notes.txt: YARA.thm_demo_rule.UNOFFICIAL FOUND

```

We have especially written a rule for AV-checker. Binary is being catched as malicious. What about `notes.txt`
which is also detected as malicious. Because the text contains the same path which we specified the rule earlier.

We can improve our Yara rule to identify the file with `hxd` which is a freeware Hex editor.


Do not forget that `EXE` files start with `4D 5A` and ASCII `MZ` so that means we can add this rule into our script

```
rule thm_demo_rule {
	meta:
		author = "THM: Intro-to-AV-Room"
		description = "Look at how the Yara rule works with ClamAV"
	strings:
		$a = "C:\\Users\\thm\\source\\repos\\AV-Check\\AV-Check\\obj\\Debug\\AV-Check.pdb"
		$b = "MZ"
	condition:
		$b at 0 and $a
}

```
We just updated the rule `Desktop\Files\thm-demo-2.yara` 

1. ($b) is equal to `MZ` as an identifier
2.  We also used AND operator for both definitions in 1 and 2 are found.
3.  So, we can implement to our rule and make the process easier.


This will be the result.


```
C:\Users\thm>"c:\Program Files\ClamAV\clamscan.exe" -d Desktop\Files\thm-demo-2.yara Desktop\Samples
Loading:     0s, ETA:   0s [========================>]        1/1 sigs
Compiling:   0s, ETA:   0s [========================>]       40/40 tasks

C:\Users\thm\Desktop\Samples\AV-Check.exe: YARA.thm_demo_rule.UNOFFICIAL FOUND
C:\Users\thm\Desktop\Samples\backdoor1.exe: OK
C:\Users\thm\Desktop\Samples\backdoor2.exe: OK
C:\Users\thm\Desktop\Samples\eicar.com: OK
C:\Users\thm\Desktop\Samples\notes.txt: OK

```


As you can see we just improved our Yara rule to make it more abstract. AV vendors are fighting against malwares. Malware analysts
should be careful with their work and be constantly working and improving the databases.
More importantly, it shall also be handy to analyze binaries. Now we will look at the security engine called `kaspersky scan engine` we will also reverse malware protection engine to have a better understanding about
security and threat hunting.


# Kaspersky-AV security engine

Let me introduce a bit about `kaspersky-scan engine` which we also called server-side security solution system that has a functionality to secure HTTP traffic scanning as well as file and URL checking 
to control whether has been attacked or not. Kaspersky scan engine delivers a lot of comprehensive protections which against trojan,malware,spyware,rootkits, etc..
You can request the KAV SDK lab which is developed by kaspersk developers.

 I have already mentioned about `signature analysis` which scans and identfies the hashes or well predifined strings in scanned files. This method includes based on the hash of the entire malicious file. Kaspersky has a tradiontal structurei
 to perfom such analysis such as heuristic and smarthash analysis this provides us that this detection can also detect unknown polymorphic malware.
 
 
 I have covered a bit about `heuristic` scan. Let me explain a bit more about this technique.Static heuristic engines are implemented in many different ways depending
 on the deployment target. Heuristic scan which are based on machine learning algorithm, such as genetic network, neural network, etc..
 Heuristic engines are better deployed in malware malware research because it can be caused a lot of false positivies.
 
- Is the file structure uncommon?
- is it using some tricks to fool a human?
- is the icon being changed?
 
 Heuristic engine that implements a set of algorithm will help us to detect malicious files. Kaspersky has this functionality.
 
 I have also covered about `smarthash` this is the technology of machine learning as well.
 
 This functional is a kaspersky lab patented algorithm for building intelligent, such as identifying sensitive hashes. Those files can be extracted
 and quantized. Smarthash also allows for the identification of clusters similar files and effective detectetion system line by line.
 This technique utilizes several precision levels for the detection of even high polymorphic malware.
 
 Smart-hash has great features and benefits such as:
 
 - it detects within minutes immediately
 - it works online as well offline
 - Strength against new, evasive, and polymorphic malware
 - by help of SmartHash technique it results  in minimal false positives and yields a high detection rate.

Smart-hash has been considering updated because it besides detectetion functionality. This technique improves of the power of kaspersky lab whitelisting capabilities.
Smart-hash calculates on the client side and can be compared against well-known good files in the kaspersk-lab databases through kaspersky security network.


When we compare with other AV technologies, we see that Kaspersky scan engines technology, that Robots process the sandbox logs line by line. The execution logs of new malicious samples are studied by using Machine Learning, to find new detection indicators
The help of this method is being used by heuristic analysis and the report will be delivered to analysts.

Kaspersky scan engines understands more than 4000 different formats such as,zip,pdf,exe of compressed archives.


When you have decided to use advanced heuristic analysis, this technique provides us that any executable files
or scripts, that kaspersky emulates its execution in a secure artificial environment. When kaspersky identfies a suspicious activity
is discovered during analysis of the behavior from that emulated object. This will be considered as malicious thus it shall help to detect new and unknown malcious file.






# Kaspersky-AV - RE Analysis with dnSpy

This part will not be easy for me. It is my first time to reverse an AV detector. We are going to reverse `kaspersky's malware protection engine`. First of all, i should create a fileless malware to see the behavior
Afterwards, I am going to check the .dll files of kaspersky to see the catch operation of kaspersky. Let me check the files.... We need to find the rigth file to reverse it.


![image](https://user-images.githubusercontent.com/95978207/195069996-535c0a89-88ec-4a47-8784-7079edb06e88.png)

As you can see we have a lot dll file now our goal is to check the right dll file to be reversed properly. It is useful to look at the running services such as:

![image2](https://user-images.githubusercontent.com/95978207/195076934-3e36bea9-5319-41d4-bcde-34a65b04ba16.png)


Because we need to specify the scheduled processes, and we see that avp.exe is running so, it will be useful to disassamble or decompile this .exe file

I am going to decompile this file:

Let me say something, when I was going to check `avp.exe and avpui.exe` I was facing with lot of functions:

```

uint ___get_entropy(void)

{
  DWORD DVar1;
  uint local_18;
  uint local_14;
  _FILETIME local_10;
  uint local_8;
  
  local_10.dwLowDateTime = 0;
  local_10.dwHighDateTime = 0;
  GetSystemTimeAsFileTime(&local_10);
  local_8 = local_10.dwHighDateTime ^ local_10.dwLowDateTime;
  DVar1 = GetCurrentThreadId();
  local_8 = local_8 ^ DVar1;
  DVar1 = GetCurrentProcessId();
  local_8 = local_8 ^ DVar1;
  QueryPerformanceCounter((LARGE_INTEGER *)&local_18);
  return local_14 ^ local_18 ^ local_8 ^ (uint)&local_8;
}

```

It is well known that `entropy` is important to identify to be made malware. The key part of antivirus evasion is determing how malware is detected.
Thus some signature sample detected via static analysis, which means using some signature, or is it detected
through dynamic techniques such as monitoring behaviour for suspicious actions.

Shannon entropy can be a good indicator. I am not going to explain what an `entropy` is however,let me mention that entropy signature will calculate the entropy level of a file.

While threat hunting we should understand that some files that we need to concern on such as the entropy level of that file 
- Legitimate files tend to have an entropy between 4.8 and 7.2
- As we already quess that above 7.2 entropy tend to be malicious.
- By the researchers that said, nearly, %30 of all of the malicious samples have an entropy near 8.0 while only %1 of legtimate samples have entropy of 8.0
- When you are facing that samples have an entropy above 7.2 that means approximately %55 can be flagged as malicious.



Turn back to our research. I am also going to check this file whether is packed or not. Let me check with our useful tool `PeStudio`

```
first-bytes-hex,4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 
first-bytes-text,M Z .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. @ .. .. .. .. .. .. .. .. 
file-size,256040 bytes
entropy,6.687
entry-point,E8 AF 04 00 00 E9 68 FE FF FF 55 8B EC 81 EC 24 03 00 00 53 6A 17 E8 8E 50 01 00 85 C0 74 05 8B 4D 
file-version,21.3.10.391
description,Kaspersky Anti-Virus Command Line
file-type,executable
cpu,32-bit

```


I would like to watch my process to see whether other dll files are running. This part is important you do not know which processes are running. You should be able to use process hacker or you can use process explorer.
After checking the processes you shall see `avp.exe` hmm interesting this means that this process is only based on antivirus.

```
svchost.exe, 808, , , 1.36 MB, NT AUTHORITY\SYSTEM, Host Process for Windows Services
svchost.exe, 4116, , , 1.31 MB, NT AUTHORITY\SYSTEM, Host Process for Windows Services
msiexec.exe, 4496, , , 9.91 MB, NT AUTHORITY\SYSTEM, Windows® installer
svchost.exe, 1160, , , 976 kB, NT AUTHORITY\SYSTEM, Host Process for Windows Services
avp.exe, 6204, 0.16, 1.88 kB/s, 179.69 MB, NT AUTHORITY\SYSTEM, Kaspersky Lab launcher <-------- this one
avpui.exe, 6280, 0.06, , 79.01 MB, DESKTOP-AURG0E4\d4rk, Kaspersky Anti-Virus 
ksde.exe, 6572, , , 27.97 MB, NT AUTHORITY\SYSTEM, Kaspersky Lab launcher
ksdeui.exe, 5792, , , 8.22 MB, DESKTOP-AURG0E4\d4rk, Kaspersky Secure Connection
lsass.exe, 648, , , 6.22 MB, NT AUTHORITY\SYSTEM, Local Security Authority Process
fontdrvhost.exe, 788, , , 1.25 MB, Font Driver Host\UMFD-0, Usermode Font Driver Host
winlogon.exe, 556, , , 2.59 MB, NT AUTHORITY\SYSTEM, Windows Logon Application
fontdrvhost.exe, 792, , , 1.76 MB, Font Driver Host\UMFD-1, Usermode Font Driver Host
dwm.exe, 6716, 0.71, , 58.22 MB, Window Manager\DWM-1, Desktop Window Manager
explorer.exe, 4456, 0.36, , 45.76 MB, DESKTOP-AURG0E4\d4rk, Windows Explorer
vmtoolsd.exe, 5996, 0.19, 684 B/s, 22.95 MB, DESKTOP-AURG0E4\d4rk, VMware Tools Core Service
ProcessHacker.exe, 2512, 6.17, , 14.74 MB, DESKTOP-AURG0E4\d4rk, Process Hacker
ConEmu64.exe, 4388, 0.45, , 12.1 MB, DESKTOP-AURG0E4\d4rk, Console Emulator (x64)
ConEmuC64.exe, 5284, 0.55, 52.93 kB/s, 2.5 MB, DESKTOP-AURG0E4\d4rk, ConEmu console extender (x64)


```


Oke, after this check up we are seeing that it makes a secure connection through `kaspersky vpn` but for this part we are not interested in that case. I will walk-through step by step the process.,,

I was going to check the current processes. I saw immediately that PID of avp was 6204 that's great. In order to get more detail more about this process I am going to dump this process.

`process hacker` will be useful in this case because we can also identfy the service which is running behind this process, and we see that `kaspersky lab launcher` is running.


You can install `flare-vm` onto your computer because it makes your work much more easier. First of all, you can the process via `detect it easy` to control the entropy. When you realize
that entropy is high we can understand from this that can be packed as well obfuscated or either.

When you understand this step, it is also important that the image type which is in our case `32 bit`


![image](https://user-images.githubusercontent.com/95978207/195560281-18fbb336-dc28-4d61-a6d2-2a108d1549cd.png)



We understand from this table that `.text` is not packed, and is it written in C# or cpp we shall see. We are going to dump `avp.exe` to see the all memory into this exe file.


```


Users\d4rk\Desktop\AV-dump+>pd32.exe -pid 1528
Process Dump v2.1
  Copyright ┬⌐ 2017, Geoff McDonald
  http://www.split-code.com/
  https://github.com/glmcdona/Process-Dump


Loading clean hash database from 'C:\ProgramData\chocolatey\lib\processdump.fireeye\tools\ProcessDump\clean.hashes'.
Did not find an existing clean hash database, using an empty one.
dumping process avpui_exe with pid 0x5f8...
... building import reconstruction table ...
 dumping 'exe' at 560000 to file 'avpui_exe_PID5f8_avpui.exe_560000_x86.exe'
 dumping 'dll' at 2C00000 to file 'avpui_exe_PID5f8_hiddenmodule_2C00000_x86.dll'
 dumping 'dll' at 7380000 to file 'avpui_exe_PID5f8_hiddenmodule_7380000_x86.dll'
 dumping 'dll' at 7680000 to file 'avpui_exe_PID5f8_hiddenmodule_7680000_x86.dll'
 dumping 'dll' at 7720000 to file 'avpui_exe_PID5f8_hiddenmodule_7720000_x86.dll'
 dumping 'dll' at 7730000 to file 'avpui_exe_PID5f8_hiddenmodule_7730000_x86.dll'
 dumping 'dll' at 7740000 to file 'avpui_exe_PID5f8_hiddenmodule_7740000_x86.dll'
 dumping 'dll' at 7D20000 to file 'avpui_exe_PID5f8_hiddenmodule_7D20000_x86.dll'
 dumping 'dll' at A1D0000 to file 'avpui_exe_PID5f8_hiddenmodule_A1D0000_x86.dll'
 dumping 'dll' at A260000 to file 'avpui_exe_PID5f8_hiddenmodule_A260000_x86.dll'
```


It will be really useful to scan all dll files through `detect it easy` because this tool will show us what kind of compiler are those files being compiled.
Let me now use it and be waiting the result.


```
C:/Users/d4rk/Desktop/hiddennn-kaspersky/avpui_exe_PID5f8_hiddenmodule_FC70000_x86.dll 163 msec
PE32
    Library: .NET(v4.0.30319)
    Linker: Microsoft Linker(48.0)[DLL32,signed]

C:/Users/d4rk/Desktop/hiddennn-kaspersky/avpui_exe_PID5f8_hiddenmodule_FE10000_x86.dll 82 msec
PE32
    Library: .NET(v4.0.30319)
    Linker: Microsoft Linker(8.0)[DLL32,signed]

C:/Users/d4rk/Desktop/hiddennn-kaspersky/avpui_exe_PID5f8_hiddenmodule_FE20000_x86.dll 91 msec
PE32
    Library: .NET(v4.0.30319)
    Linker: Microsoft Linker(48.0)[DLL32,signed]

C:/Users/d4rk/Desktop/hiddennn-kaspersky/avpui_exe_PID5f8_hiddenmodule_FFE0000_x86.dll 84 msec
PE32
    Compiler: MASM
    Linker: Microsoft Linker(14.10, Visual Studio 2017 15.0*)[DLL32,signed]

```
We should understand from this result that some of them are being compiled with .NET and some of them MASM,VB thus our goal is analyzing this file step by step.


I am going to take a look  `avpui_exe_PID5f8_hiddenmodule_FFE0000_x86.dll`


![image](https://user-images.githubusercontent.com/95978207/196040240-2e1aea72-62b9-4463-b57c-01b96da04fa3.png)

from this result we are not seeing anything useful.


Let me analyze further. We should be able to view those dlls in Ilspy to get the right source code.

I found an interesting source code. I am willing to analyze further here is the source code :


```csharp

public static class DetectTypeConverters
	{
		
		public static DetectType GetDetectType(this Threat threat)
		{
			Guard.ArgumentIsNotNull<Threat>(threat, null, new object[0]);
			return DetectTypeConverters.CorrectDetectType((DetectType)threat.ThreatType, (DetectDanger)threat.DangerLevel);
		}

		
			if (detectType == DetectType.Malware && detectDanger != DetectDanger.High)
			{
				return DetectType.MalwareMediumDanger;
			}
			return detectType;
		}
	}

```

You can easily read from this code that it detects whether medium or not. We need to analyze this code more in depth. Let me show you the `ThreatType` because there we will see what the medium threats are.


We can also see if the detectype thus anything like; url,file, etc  will be detected by Kaspersky-AV and if it is not dangerous but well being infected then it will control what kind of malware family is being thrown.



```csharp

public enum DetectType : uint
	{
		// Token: 0x0400010B RID: 267
		Unknown,
		// Token: 0x0400010C RID: 268
		Virware,
		// Token: 0x0400010D RID: 269
		Trojware,
		// Token: 0x0400010E RID: 270
		Malware,
		// Token: 0x0400010F RID: 271
		Adware,
		// Token: 0x04000110 RID: 272
		Pornware,
		// Token: 0x04000111 RID: 273
	
```
There are a lot, but I just want to show you when the threat has medium severity. Let me analyze further.

We also seen `detecttype` let me show you the enum:



```csharp


public unsafe Threat() : base(new StructHolder(calli(System.Void* modopt(System.Runtime.CompilerServices.CallConvCdecl)(), <Module>.?m_api@?$StructApiHolder@UThreat@antimalware@@@Details@NativeInterop@Platform@KasperskyLab@@2UStructApi@2345@B), 
*(ref <Module>.?m_api@?$StructApiHolder@UThreat@antimalware@@@Details@NativeInterop@Platform@KasperskyLab@@2UStructApi@2345@B + 8)), 224115031U)
```


```System.Runtime.CompilerServices.CallConvCdecl)()``` Provides functionality for compiler writers who use managed code to specify attributes in metadata that affect the run-time behavior of the common language runtime.
```CallConvCdecl()``` The caller cleans the stack. This enables calling functions with varargs. This class is used only as a custom modifier of the metadata signature of a method





When the detectDanger is not high but when its been infected then it will return as severity(medium). I need to consider that functions are calling from OS because lets assume when we drop a file to 
kaspersky it should use system behavior internals to be able to detect the file.



```csharp

public enum DetectDanger
	{
		// Token: 0x04003E22 RID: 15906
		Unknown = 0,
		// Token: 0x04003E23 RID: 15907
		High = 1,
		// Token: 0x04003E24 RID: 15908
		Medium = 2,
		// Token: 0x04003E25 RID: 15909
		Low = 4,
		// Token: 0x04003E26 RID: 15910
		Informational = 8,
		// Token: 0x04003E27 RID: 15911
		All = 15
	}
```

I think that each represents as an integer, and in our case we are controlling the medium severity than it should be 2 and if it is all that it should be 15 because they are suming up by kaspersky 
When its being 2 than it will return to medium.


```csharp


// Token: 0x020001A7 RID: 423
	[Flags]
	public enum DetectDanger
	{
	
```

I am giving the same source code because we have forgotten to include `[flags]` this is an API did you know? 


`FlagsAttribute Class`

which Indicates that an enumeration can be treated as a bit field; that is, a set of flags. You can get more information about this API.

There is a sample code given on Microsoft docs


```csharp


   // Define an Enum with FlagsAttribute.
   [Flags]
   enum MultiHue : short
   {
      None = 0,
      Black = 1,
      Red = 2,
      Green = 4,
      Blue = 8
   };

```
```

All possible combinations of values with FlagsAttribute:
//         0 - None
//         1 - Black
//         2 - Red
//         3 - Black, Red
//         4 - Green
//         5 - Black, Green
//         6 - Red, Green
//         7 - Black, Red, Green
//         8 - Blue
//         9 - Black, Blue
//        10 - Red, Blue
//        11 - Black, Red, Blue
//        12 - Green, Blue
//        13 - Black, Green, Blue
//        14 - Red, Green, Blue
//        15 - Black, Red, Green, Blue
//        16 - 16


```



You are seeing that instead of passing the flags it is suming up together because `black` and `red` if we sum up you will get 3 but if we did not include `flags` then the result would be:

1 + 2 = 3 and that should be 3 but the problem it will be equal to 3 not the flag thus it is not going to be flagged ans that is the reason why Kaspersky uses flags to detect it easier.





Hopefully, you understood this process. Now, we are goig to analyze it further. 


We are now focusing on `web-browser` technique, we will be looking how AV detects hashes, threatname,etc...


```csharp

public void OpenThreatSecureList(string threatName, string hash, string itemPath)
{
	WebBrowserLauncher.OpenInDefaultBrowserAsync(this._productUrlProvider.Value.VirusListThreatLink(threatName, hash, itemPath));
}


```

We are seeing that it lauches through webBrowser and threat,hash, itempath are given to the function 


```csharp

public interface IThreatUrlProvider
	{
		
		string VirusListThreatLink(string threatName, string hash, string itemPath);
	}

```
it seems we have virusListThreatLink now this should take the threatName and the hash from that file, also itempath this should be the path of that file it needs to identify and deletes whether the file is being malicious or not.


I also need to analyze where it takes the hashes. We already mentioned that hashes are important with that purpose AV products will be able to delete the file if it is being malicious.



```csharp

private static string GetFileName(string objectName)
{
	bool flag = objectName.Contains("//");
	string result = objectName;
	if (flag)
	{
		result = objectName.Substring(0, objectName.IndexOf("//", StringComparison.Ordinal));
	}
	return result;
}

```

There is a bool flag which means it should identfy if the objectname contains `//` then will it be true and the result will return to another function.Lets research further with our research



```csharp

public override Option<ProcessInfo> TryGetProcessInfo(ulong pid)
{
	if (pid == 0UL)
	{
		return Option.None<ProcessInfo>();
	}
	ProcessInfo processInfo;
	ResultCode processInfoByPid = this._processInfoProvider.GetProcessInfoByPid((int)pid, ref processInfo);
	if (processInfoByPid == null)
	{
		return Option.Some<ProcessInfo>(processInfo);
	}
	this.Tracer.TraceWarning("Can't get information about process with pid 0x{0:X}, {1}", new object[]
	{
		pid,
		processInfoByPid
	});
	return Option.None<ProcessInfo>();
}

```

Lets overview this code. It seems that it definetly uses windows API you can get more information from: [processInfo](https://learn.microsoft.com/en-us/dotnet/api/system.web.processinfo?view=netframework-4.8)
ProcessInfo: Provides information on processes currently executing.

1. In order to catch the malware it is important to detect the process information. If the processInfo is not found `0ul` represents as long zero then it will return option none


It indicates processInfo through windwows API, .NET framework. Thus it will be easier to return processInfo of that that file.After finding the processPıd and processInfo it will return with or not information it depends on scanning of AV.



As I mentioned there a lot of functions that we need to cover but I will only cover the important part. I am going to analyze my research further.







It is not only about checking the dll files because as you open a dll, we will be able to see:

![image](https://user-images.githubusercontent.com/95978207/196729214-10871898-e3ee-4d52-8ed6-0cf78a83e9c4.png)




We should check step by step because hidden modules can be popped up immediately when we are checking the dll. You can also run the dll with rundll32.exe 'file.dll' Now we will analyze it further.








Now, we are going to analyze HTTP alert severity. Lets look into our code.


```csharp

private static AlertSeverity GetHttpscanAlertSeverity(DetectDanger detectDanger)  <---
{
	switch (detectDanger)
	{
	case 1:
		return AlertSeverity.High;
	case 2:
	case 4:
		return AlertSeverity.Medium;
	case 3:
		break;
	default:
		if (detectDanger == 8)
		{
			return AlertSeverity.Low;
		}
		break;
	}
	throw new NotSupportedException(detectDanger.ToString());
}

```

First of all, I am going to illustrate `alertseverity` here is the source code:

```csharp

namespace KasperskyLab.UI.Platform.Services.Alerts
{
	// Token: 0x02000133 RID: 307
	public enum AlertSeverity
	{		High,
		
	     	Medium,
		
		    Low
	}
}
```
An `enum` is a special "class" that represents a group of constants (unchangeable/read-only variables).



 At this source code we should be able to understand that `alertseverity` has 3 severity 
 
 - High
 - Medium
 - Low

Awesome now let me research this snippet code further.



We have a switch case which tells us the severity of alerts, and we have cases which return integers type. If we combine together we shall see that those functions are being associated

Let me show the source code.



```
AlertTracer.TraceProcessingInformation<AskObjectAction>(askObjectAction, "IsDetectByKsn " + threatDisinfectionAskAction.IsDetectByKsn.ToString(), new object[0]);
```

We are seeing that there is a alertTracer which can be detected by KSN(kaspersky security network): KSN has some functionality but what does it do?

The Kaspersky Security Network (KSN) infrastructure is designed to receive and process complex global cyberthreat data, 
transforming it into the actionable threat intelligence that powers our products.

Awesome let me show you the tracing progress of AV .


```csharp
if (threatDisinfectionAskAction.IsDetectByKsn && (detectType == DetectType.Unknown || detectType == DetectType.Virware || detectType == DetectType.Trojware))
		{
			return DetectGroup.KsnDetect;
		}

```

 Just easy as that when the KsnDetect has been illustrated well through a short demonstration. Kaspersky provides an image where it gives you a good idea. You can get more info from [KSN](https://www.kaspersky.com/ksn)
 
 
 ![image](https://user-images.githubusercontent.com/95978207/196989486-fc8a484a-6285-4ec4-a69d-68b969302ec7.png)
 
 
 
 This line important : `When a deployed security solution encounters anything it doesn't immediately recognize, it requests information from the cloud.`

Interesting this means it does not recognize immediately but it will take requests from the cloud. 

and at line 6: The Kaspersky Security Network instantly responds with a detection verdict or reputational information, as available. 

Awesome they give the information from cloud to the user.


Also forget to mention `Raw threat intelligence is processed using data science-based algorithms (also known as 'machine learning', an aspect of AI) under the supervision of Kaspersky experts. `
 
 
 

```csharp

private static AlertSeverity GetMailCheckerAlertSeverity(this AskObjectAction askObjectAction)
		{
			DetectGroup detectGroup = askObjectAction.GetDetectGroup();
			if (detectGroup - DetectGroup.MalwareMediumDanger <= 4)
			{
				return AlertSeverity.Medium;
			}
			return AlertSeverity.High;
		}

```

Awesome precisely being illustrated to us. We see that `private static AlertSeverity` has been defined. This code detects whether any suspicious objects is identified or not.
Let me further analyze this code.



As briefly `alertseverity` has this implementation to recognize the code.

```csharp

{
	public enum AlertSeverity
	{
		// Token: 0x040004E9 RID: 1257
		High,
		// Token: 0x040004EA RID: 1258
		Medium,
		// Token: 0x040004EB RID: 1259
		Low
	}
}
```

Let me analyze further:


```csharp

DetectType detectType = (DetectType)askObjectAction.DetectType;
	DetectDanger detectDanger = askObjectAction.DetectDanger;
	DetectStatus detectStatus = askObjectAction.DetectStatus;
	


````
As you can see we have detectType which is equal to objectAction I suppose this will be equal to the action of the file that is running on.
We also have detectDanger it's been defined to the file with the danger severity.
Lastly, the status of the file which is also important.

You might be wondering what `SwAlertType` is right?

here is the source code let's analyze it:


```csharp

public static SwAlertType GetSwAlertType(this AskObjectAction askObjectAction)
		{
			Guard.ArgumentIsNotNull<AskObjectAction>(askObjectAction, null, new object[0]);
			PragueTaskId taskId = askObjectAction.GetTaskId();
			Guard.Assert(taskId == 32 || taskId == 59 || taskId == 61, "taskId == PragueTaskId.Sw2 || taskId == PragueTaskId.BehaviorDetection || taskId == PragueTaskId.ExploitPrevention");
			
		}


```

As you can see there should be taskID which is asking for to the objectfile, when the taskId is get from `askobjection` as integer, we should not forget when its get the Id 
now it shall return as integer and set it to if condition to be checked. Hmm interesting we have `behaviorDetection` this should be checked by the behavior function which is called.
After the control this ought to be checked and return as ExploitPrevention where it will be called from another function which is waiting. I know that can be complicated when you ar trying to understand the source code.

By confuser or other such techniques you can use API hooking to analyze more in depth [JIT-hooking](https://github.com/Elliesaur/TinyJitHook) You can use this technique when you need it.





I know that this should not be enough to understand AV products properly, but it was my first time to analyze AV product however, do not forget that  we will be going to analyze more AV products. I will come with more awesome techniques which shall make it easier for us.



Thank you for reading this blog. Stay tuned for more great blogs.


Ahmet Göker | RE
