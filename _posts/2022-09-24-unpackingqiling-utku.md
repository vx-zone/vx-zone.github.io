---
layout: post
title: Unpacking PE with Qiling
date: 2022-10-01 14:14:42 +0300
description: Heyy gather round! We'll unpack the file with Qiling.
author: Utku Çorbacı
comments: true
tags: [Unpacking, Emulation, EN]
---

In this blog post, we have a packed PE file. We will analyze it and unpack it with Qiling Framework. Once you understand how encryption works, I will explain more about Qiling. In this article we will use Cutter for analysis and Ghidra for decompile (included in Cutter).

# Table Of Contents
<pre>
1. Analysis Packed Sample
    1.1 Detect It Easy Output
    1.2 Packer Basics
    1.3 Cutter - Ghidra (Disassemble & Decompile)
2. Automate Unpacking with Qiling
    2.1 Qiling Framework Structure
    2.2 Layle's Emu Analysis
    2.3 The Troubles
</pre>

# Analysis Packed Sample

## Detect It Easy Output
The first thing I would do for analysis is to scan the file into [Detect It Easy](https://github.com/horsicq/Detect-It-Easy). On the Detect It Easy screen, it says that it contains the usual protections. But we know that Sample doesn't. To investigate why, I'll look at how Detect It Easy does this. 

```
PE: protector: PELock(-)[-]
PE: protector: Unopix(0.94)[-]
PE: linker: Microsoft Linker(14.33**)[EXE32,console]
```
In fact, it is not difficult to understand how he did it. When we switch to the Signatures tab, we see that all kinds of identifiable things have rules. Here we need to look at PELock. This signature name is _PELock.2_ and code is below:

```
function detect(bShowType,bShowVersion,bShowOptions)
{
    if(PE.getNumberOfImports()==1)
    {
        if((PE.isLibraryFunctionPresent("KERNEL32.DLL", "LoadLibraryA"))!=-1&&
           (PE.isLibraryFunctionPresent("KERNEL32.DLL", "VirtualAlloc"))!=-1)
        {
            if(PE.getNumberOfResources()>=1)
            {
                if(PE.getNumberOfSections()>=4)
                {
                    if((PE.getSectionName(0)==PE.getSectionName(1))&&(PE.getSectionName(0)==PE.getSectionName(3)))
                    {
                        bDetected=1;
                    }
                }
            }
        }
    }
    return result(bShowType,bShowVersion,bShowOptions);
}
```
The first thing it does is that there is "only" Kernel32.dll on the Import Table. Secondly, does it have LoadLibraryA and VirtualAlloc? Thirdly, it checks the number of Resources and Sections and checks if some of the section names are equal to each other. 

The Unopix protection (first time I've seen it) works like this:

```
function detect(bShowType,bShowVersion,bShowOptions)
{
    var nLastSection=PE.nLastSection;
    if(nLastSection>=2)
    {
        var nVirtualSize=PE.section[nLastSection].VirtualSize;
        if(nVirtualSize==0x1000)
        {
            var nRawSize=PE.section[nLastSection].FileSize;
            if(nVirtualSize==nRawSize)
            {
                var nFlags=PE.section[nLastSection].Characteristics;
                if((nFlags==0xe0000040)&&(PE.section[nLastSection].Name!=".!ep"))
                {
                    sVersion="0.94";
                    bDetected=1;
                }
            }
        }
    }
    return result(bShowType,bShowVersion,bShowOptions);
}
```

I will not explain what he did because it is very clear. 
Summary: PELock and Unopix(?) show undesirable results in Detect It Easy because they display a similar representation. 
What I mainly want to do here is to compare EntryPoint and Sections in PE Info by pressing the PE button.
I will find the place in Section that matches the address we see in AddressOfEntryPoint (00022000). 

![Screenshot_1](https://user-images.githubusercontent.com/54905232/192118627-c7daff68-eee5-447f-aec5-97f3826b4db0.png)

If we look at the virtual address of the section named _.shell_, we will see that it matches the entrypoint. 

## Packer Basics
There are many sources written about this. But it would be wrong to start the analysis without writing about it. Most packers work the same way. To simplify our interpretation, I will first briefly explain how they work. 
Packer encrypts the .text section containing executable code.  It then inserts a new section into the file and changes the Entry Point accordingly. The new section does the decryption of the encrypted section (unpacking). The decrypted codes are then executed in memory.

For example, the data encryption function of the packer we analyzed:
{% highlight c %}
// Encrypt the load segment and transformed import table.
EncryptData(load_seg_base, load_seg_size + new_imp_table_size);

//-----------------------------------------------------------

void EncryptData(BYTE* const base, const DWORD size) {
    if (size == 0) {
        return;
    }
    assert(base != NULL);

    for (DWORD i = 0; i != size; ++i) {
        base[i] += 0xCC;
    }
}
{% endhighlight %}

My goal in this article is not to dump in an executable way (i.e. I will not fix the IAT table after dumping). After Decryption with Qiling, we will take a look at the sections. For example, an image of a sample partition before it is unpacked:
![Screenshot_3](https://user-images.githubusercontent.com/54905232/192287029-6065922e-dd2b-4b14-bc99-9c301d36f55f.png)

After unpacking:
![Screenshot_4](https://user-images.githubusercontent.com/54905232/192372646-07fe7938-94a1-42ab-9f82-ad71e35549e0.png)

## Cutter - Ghidra (Disassemble & Decompile)
We already knew that the file was encrypted by the deletion of the partition names. The entry point of the file we have is redirected to the address of the partition named _.shell_ . After opening the Cutter, we already see one function in the functions section and we start to analyze it.
This is what we will see on the graph when we open the file on Cutter (in read mode):
![Screenshot_2](https://user-images.githubusercontent.com/54905232/192118879-0b78a4b3-dd50-4e4a-813d-c8e925298adc.png)

I will use _Ghidra_ since it is more difficult to interpret such packing operations in assembly. Once we figure out how it works, we can use x32dbg and Scylla. 

We will see while debugging, but there are some things I want to report first. Structures like [ebp + 24] that we see in assembly commands are local variables defined at the beginning of the program.
Local variable definition:

```
;-- (0x0042202e) GetProcAddress:
0x0042202d      add     byte [ebx + 0x20], cl
0x00422030      .dword 0x205c0002
;-- GetModuleHandleA:
0x00422032      .dword 0x0002205c ; reloc.Kernel32.dll_GetModuleHandleA
;-- LoadLibraryA:
0x00422036      .dword 0x0002206f ; reloc.Kernel32.dll_LoadLibraryA
```

For example, we see that the packer initially uses the following commands to access some Windows APIs:
{% highlight nasm %}
; Get the address of `VirtualAlloc` API.
lea     esi, [ebp + (dll_name - boot_seg_begin_lbl)]
push    esi
call    dword ptr [ebp + (second_thunk - boot_seg_begin_lbl)]
lea     esi, [ebp + (virtual_alloc_name - boot_seg_begin_lbl)]
push    esi
push    eax
call    dword ptr [ebp + (first_thunk - boot_seg_begin_lbl)]
mov     dword ptr [ebp + (virtual_alloc_addr_boot - boot_seg_begin_lbl)], eax
{% endhighlight %}

In Disassemble code:

```
0x004220c1  lea  esi, [ebp + 0x9e]
0x004220c2  mov  ch, 0x9e   ; 158
0x004220c4  add  byte [eax], al
0x004220c6  add  byte [esi + 0x50], dl
0x004220c9  call dword [ebp + 0x2e] ; 46
0x004220cc  mov  dword [ebp + 0xab], eax
```

{% highlight c %}
uint64_t entry0(void)
{
    uint8_t uVar1;
    int32_t iVar2;
    char *pcVar3;
    char *pcVar4;
    uint64_t uVar5;
    
    // [09] -rwx section size 4096 named .shell
    (*_GetModuleHandleA)();
    *(code **)0x4220ab = (code *)(*_GetProcAddress)();
    *(int32_t *)0x4220af = (**(code **)0x4220ab)();
    // WARNING: Call to offcut address within same function
    func_0x00422129();
    *(int32_t *)0x422125 = *(int32_t *)0x4220af + -0x422129;
    uVar5 = (*(code *)0x0)();
    uVar1 = in((int16_t)(uVar5 >> 0x20));
    pcVar3 = *(char **)0x422008;
    pcVar4 = *(char **)0x42200c;
    for (iVar2 = *(int32_t *)0x422010; iVar2 != 0; iVar2 = iVar2 + -1) {
        *pcVar4 = *pcVar3 + '4';
        pcVar3 = pcVar3 + 1;
        pcVar4 = pcVar4 + 1;
    }
    return uVar5 & 0xffffffff00000000 | (uint64_t)((uint32_t)uVar5 & 0xffffff00 | (uint32_t)uVar1);
}
{% endhighlight %}

The code is missing, some parts are not interpreted as functions, so the decompiler cannot detect them. Junk code added in the packer also shows the decompiler as broken, for example the function "func_0x00422129". So let's try to go through disassembly.

Our goal here is to dump the software from memory after decrypting the sections. So we will examine the decrypt instructions on disassembly.
```
;  DecryptData proc    src: dword, dest: dword, count: dword
0x0042212c  pushal
0x0042212d  mov   ecx, dword [ebp + 0x10]   ;count
0x00422130  mov   esi, dword [ebp + 8]  ;src
0x00422133  mov   edi, dword [ebp + 0xc] ;dest
0x00422136  jmp   0x42213d
0x00422138  lodsb al, byte [esi]
0x00422139  sub   al, 0xcc   ; 204
0x0042213b  stosb byte es:[edi], al
0x0042213c  dec   ecx
0x0042213d  or    ecx, ecx
0x0042213f  jne   0x422138
```
This part does the opposite of the _EncryptData()_ function. The reason why this function is executed several times is that all data is encrypted with the same function. 

Ok, our goal here is to dump the partitions from memory immediately after the decrypt procedure. Actually unpacking exactly is very easy with Qiling. But I won't go into IAT build in this article. I want to talk about an example project that does this. The project is vacation3-emu, which emulates Layle's vac3 modules.

And here is the function that decrypts the sections:
{% highlight nasm %}
; DecryptSections
mov edx, 0x22B   ; ptr ORIGIN_PE_INFO               
add edx, ebp                     
lea edx, dword ptr ds:[edx + 0x10] ; [edx].section_encry_info
mov eax, dword ptr ds:[edx] ; eax = [edx].sec_rva
jmp 0x9500C0                    
mov esi, dword ptr ss:[ebp + 0x45B]
add esi, eax                     
mov edi, esi                     
mov ecx, dword ptr ds:[edx + 0x4]  
push ecx                        
push edi                        
push esi                        
call dword ptr ss:[ebp + 0x457]   
add edx, 0x8                     
mov eax, dword ptr ds:[edx]      
or eax, eax                      
jne 0x9500A5                    
{% endhighlight %}

{% highlight c %}
typedef struct _ORIGIN_PE_INFO {
    //! The offset, relative to the shell.
    DWORD entry_point;

    //! The offset of the original import table, relative to the load segment.
    DWORD imp_table_offset;

    //! The relative virtual address of the relocation table.
    DWORD reloc_table_rva;

    //! The image base.
    VOID* image_base;

    //! The encryption information of sections, up to 0x40 sections and a blank structure.
    ENCRY_INFO section_encry_info[MAX_ENCRY_SECTION_COUNT + 1];

} ORIGIN_PE_INFO;

{% endhighlight %}


If we analyze it dynamically on x32dbg. We see that after decrypting the data, it jumps to [ebp+0xAF] which it stores locally. Here are the codes that decrypt the sections.

```
008F20E3 | 6A 00          | push 0x0                       
008F20E5 | FF95 AB000000  | call dword ptr ss:[ebp+0xAB]   
008F20EB | 8985 AF000000  | mov dword ptr ss:[ebp+0xAF],eax
........
```



# Automate Unpacking with Qiling
In this section we will see some of the functions in the Qiling Framework and then we will develop a software that automatically decodes and dump partitions. Since most API implementations of the Qiling Framework on Windows are missing, I will also show how to hook some functions (I may even post a PR for them later).

First, let's take a look at what exactly the Qiling Framework is.

## Qiling Framework Structure
Since the previous blog post in vx.zone went into historical details about qiling, I would like to be more specific. Unicorn is a CPU emulator. It is simply a framework that can only emulate processor instructions. Qiling is a high-level framework that covers that too and can even emulate operating system files. Based on this information, when we look at the structure of the Qiling project on GitHub, we see several features implemented in detail. 

For example, most famous file structures are defined in the loader folder:

```
qiling\qiling\loader
qiling\qiling\loader\macho_parser
qiling\qiling\loader\__init__.py
qiling\qiling\loader\blob.py
qiling\qiling\loader\dos.py
qiling\qiling\loader\elf.py
qiling\qiling\loader\evm.py
qiling\qiling\loader\loader.py
qiling\qiling\loader\macho.py
qiling\qiling\loader\mcu.py
qiling\qiling\loader\pe_uefi.py
qiling\qiling\loader\pe.py
```

This folder is important. Because we are going to implement some unimplemented windows apis using the _pe.py_ file here. I will give a small spoiler. For example, we will use the Process structure in _pe.py_ to emulate the _GetModuleHandleA_ function. 

{% highlight python %}
class Process:
    # let linter recognize mixin members
    cmdline: bytes
    pe_image_address: int
    stack_address: int
    stack_size: int

    dlls: MutableMapping[str, int]
    import_address_table: MutableMapping[str, Mapping]
    import_symbols: MutableMapping[int, Dict[str, Any]]
    export_symbols: MutableMapping[int, Dict[str, Any]]
    libcache: Optional[QlPeCache]

    def __init__(self, ql: Qiling):
        self.ql = ql
# .....................
{% endhighlight %}

There is an os folder to emulate other specific features of operating systems. Within the folder, there are similar features between operating systems, as well as separate files containing specific features. 

```
qiling\qiling\os\windows
qiling\qiling\os\windows\dlls
qiling\qiling\os\windows\__init__.py
qiling\qiling\os\windows\api.py
qiling\qiling\os\windows\clipboard.py
qiling\qiling\os\windows\const.py
qiling\qiling\os\windows\fiber.py
qiling\qiling\os\windows\fncc.py
qiling\qiling\os\windows\handle.py
qiling\qiling\os\windows\registry.py
qiling\qiling\os\windows\structs.py
qiling\qiling\os\windows\thread.py
qiling\qiling\os\windows\utils.py
qiling\qiling\os\windows\wdk_const.py
qiling\qiling\os\windows\windows.py
```

Of course, the processors have an arch folder to make the necessary adjustments before the emulation process. It contains implementations of many versions. For example x86.py:

{% highlight python %}
from functools import cached_property

from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_MODE_32, UC_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_16, CS_MODE_32, CS_MODE_64
from keystone import Ks, KS_ARCH_X86, KS_MODE_16, KS_MODE_32, KS_MODE_64

from qiling.arch.arch import QlArch
from qiling.arch.msr import QlMsrManager
from qiling.arch.register import QlRegisterManager
from qiling.arch import x86_const
from qiling.const import QL_ARCH, QL_ENDIAN

class QlArchIntel(QlArch):
    @property
    def endian(self) -> QL_ENDIAN:
        return QL_ENDIAN.EL

    @cached_property
    def msr(self) -> QlMsrManager:
        """Model-Specific Registers.
        """

        return QlMsrManager(self.uc)
# .....................
{% endhighlight %}

## Layle's Emu Analysis (BONUS) <3
I got permission from _layle_ for this. It's a great example of using Qiling on Windows. So we will analyze [this](https://github.com/ioncodes/vacation3-emu).

There is not much to look at in the structure of the project. For this, let's go directly into the emu.py file. When we look at the beginning of the script, I see that two Windows APIs are defined. Layle did not have the implementation of these functions in Qiling when he wrote this script, so he wrote them himself.

{% highlight python %}
def GetProcAddress(ql, address, params):
    global procs
    name = params["lpProcName"]
    dll_name = [key for key, value in ql.loader.dlls.items() if value == params["hModule"]][0]
    ql.loader.load_dll(dll_name.encode())
    try:
        addr = ql.loader.import_address_table[dll_name][name.encode()]
        procs[name] = addr
    except:
        pass

def LoadLibraryExA(ql, address, params):
    global modules
    name = params["lpLibFileName"]
    addr = ql.loader.load_dll(name.encode())
    modules[name] = addr
{% endhighlight %}

While writing the functions here, the loader structure mentioned in the "Qiling Structure" section was used. For example, what the GetProcAddress function does is to return the address where the functions in the dlls on the Import Table are located. 

After setting the classic ql variable, hooking is done using the `set_api` function.
    
{% highlight python %}
ql.set_api("GetProcAddress", GetProcAddress, QL_INTERCEPT.EXIT)
ql.set_api("LoadLibraryExA", LoadLibraryExA, QL_INTERCEPT.EXIT)
{% endhighlight %}

QL_INTERCEPT:
> POSIX system calls may be hooked to allow the user to modify their parameters, alter the return value or replace their funcionality altogether. System calls may be hooked either by their name or number, and intercepted at one or more stages: - QL_INTERCEPT.CALL : when the specified system call is about to be called; may be used to replace the system call functionality altogether - QL_INTERCEPT.ENTER : before entering the system call; may be used to tamper with the system call parameters values - QL_INTERCEPT.EXIT : after exiting the system call; may be used to tamper with the return value

The other point that attracted my attention on this script is that the function execution process that we do by moving the eip register on the debugger can be done very simply here.

{% highlight python %}
ql.run(begin=0x00402B6C, end=0x00404516) # set up routines
ql.dprint(D_INFO, "Finished setting up routines")
ql.run(begin=0x00404516, end=0x00404522) # decrypt packet with ICE
ql.dprint(D_INFO, "Finished decrypting packet with ICE key from module")
ql.run(begin=0x00404522, end=0x00406416) # decrypt section with ICE
ql.dprint(D_INFO, "Finished decryption data section with ICE key from decrypted packet")
{% endhighlight %}

When we run the function after specifying the start and end address of the function, the function is executed in the ql sandbox. For example, Layle uses the function in the file to rebuild the IAT table in the file it emulates.


## Unpacking Script
First, let us explain our purpose. We can't read the chapters because of the encrypted data. For this, we will dump the partitions after they are decrypted. After running the function that decrypts the partitions, it is enough to run the `dump_memory_region` function.

Since the starting addresses of the functions in the assembly are loaded into local variables to be executed, we must first analyze this. After initializing on x32dbg I find where the decrypt function is loaded.

{% highlight nasm %}
mov eax,0x7E
add eax,ebp
push dword ptr ds:[eax+0x4]
push 0x0
call dword ptr ss:[ebp+0xAB]
mov dword ptr ss:[ebp+0xAF],eax
{% endhighlight %}

Our target value is [EBP + 0xAF]

Only after running these parts (the addresses are known) I will change the EIP and redirect it to the address I want.
{% highlight nasm %}
pop ebp
sub ebp, 0x6
lea esi,dword ptr ss:[ebp + 0x3E]
.......................
.......................
jmp testfile-packed.EA213D
lodsb 
sub al, 0xCC
stosb 
dec ecx
or ecx, ecx
jne testfile-packed.EA2138
popad 
leave 
ret 0xC
{% endhighlight %}

Python code:
{% highlight python %}
from qiling import *    
from qiling.const import QL_VERBOSE

def dump_memory_region(ql, address, size):
    try:
        excuted_mem = ql.mem.read(address, size)
    except Exception as err:
        print('Unable to read memory region at address: {}. Error: {}'.format(hex(address), err))
        return
    print("Dumped")
    with open("unpacked_"+hex(address)+".bin", "wb") as f:
        f.write(excuted_mem)

exeFile = "testFile-packed.exe"
ql = Qiling(["testFile-packed.exe"], "qiling/examples/rootfs/x86_windows")

ql.run(end=0x00422143)

test = ql.arch.regs.read("EBP") + 0xaf # test = EBP + 0xaf
xxxx = ql.mem.read(test, 0x4) # address = [EBP + 0xaf]

print("[EBP + 0xAF]: ", hex(int.from_bytes(xxxx, byteorder='little')))

address = int.from_bytes(xxxx, byteorder='little')

ql.arch.regs.arch_pc = address
ql.arch.regs.eip = address
ql.run()

dump_memory_region(ql, 0x00419000, 0x100)
{% endhighlight %}

Output:

```
utku%> python main.py
[=]     Initiate stack address at 0xfffdd000
[=]     Loading testFile-packed.exe to 0x400000
[=]     PE entry point at 0x422000
[=]     TEB is at 0x6000
[=]     PEB is at 0x61b0
[=]     LDR is at 0x6630
[=]     Loading ntdll.dll ...
[=]     Done loading ntdll.dll
[=]     Loading kernel32.dll ...
[=]     Loading kernelbase.dll ...
[=]     Done loading kernelbase.dll
[=]     Done loading kernel32.dll
[=]     Loading ucrtbase.dll ...
[=]     Calling ucrtbase.dll DllMain at 0x10298260
[=]     GetSystemTimeAsFileTime(lpSystemTimeAsFileTime = 0xffffcfcc)
[x]     Error encountered while running ucrtbase.dll DllMain, bailing
[=]     Done loading ucrtbase.dll
[=]     GetModuleHandleA(lpModuleName = "Kernel32.dll") = 0x6b800000
[=]     GetProcAddress(hModule = 0x6b800000, lpProcName = "VirtualAlloc") = 0x6b8181b0
[=]     VirtualAlloc(lpAddress = 0, dwSize = 0xe0d, flAllocationType = 0x3000, flProtect = 0x40) = 0x50006f8
[EBP + 0xAF]:  0x50006f8
[=]     GetModuleHandleA(lpModuleName = "Kernel32.dll") = 0x6b800000
[=]     GetProcAddress(hModule = 0x6b800000, lpProcName = "VirtualAlloc") = 0x6b8181b0
[=]     VirtualAlloc(lpAddress = 0, dwSize = 0xe0d, flAllocationType = 0x3000, flProtect = 0x40) = 0x5001505
Dumped
```