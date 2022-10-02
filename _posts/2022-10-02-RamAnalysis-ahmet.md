---
layout: post
title: Memory Forensics with Rekall
date: 2022-10-02 13:58:02 +0300
description: RAM Image analysis with Rekall
author: Ahmet Göker
comments: true
tags: [Malware Analysis, Forensics, Memory Forensics, EN]
---

_“As a matter of fact, yeah, they were foolproof. The problem is that you don’t have to protect yourself against fools. You have to protect yourself against people like me.”_
-- **Jeffery Deaver**



# Table Of Contents
<pre>
0x1. Memory Forensics
    1.1 base of memory forensics
    1.2 Acquisition Process
    1.3 Volatile Memory
    1.4 Address Space
    1.5 Virtual Memory
    1.6 Paging
0x2. Rekall Memory Forensics
    2.1 Rekall structure
    2.2 Profile Mechanism
    2.3 Auto Profile Selection
0x3 Memory Dump with Rekall
    3.1 DLL
    3.2 PID Scanner malicious DLL 
0x4. Manual Mem File Analysis With Rekall
    4.1 Process Injection Detector Script
   
</pre>


**_Greetings to the best hackers in the world. Today I am going to illustrate a framework called Rekall memory analysis_**

# Memory Forensics
Today, I will explain you what ```memory Forensics``` is... Now this area is referred to as memory analysis. In this area, it is important to do your analysis of volatile data in a computer's memory dump.
Security Professionals are able to conduct such memory dump to investigate malware or other being injected process.
We will be able to investigate and doing our forensics to catch malicious behaviours that do not leave easily detectable tracks on hard drive.

## Acquisition Process
When we hear this term, we should consider this as the process of copying the contents of volatile memory(RAM). In order to have a good understanding of the process its important
to learn some memory management principles and disiciplines. In this blogpost, we will be going to extract and dump our memory to get more familiar with the process.
We will also learn a bit about live memory analysis on Windows OS.
Memory live analysis has its advantages to dig deeper into memory dump.
Now before diving into Rekall Project let me explain a bit more about acquisition Process.


### Volatile Memory
We know that this definition has to do with Random Access Memory(RAM), which stores the code and data that the process actively access and stores.
However, we ought to know that processes have not direct access to physical memory. This is because process can easily harm the operating system.
RAM is defined as volatile memory because when you powered your computer on, it requires power for the data to remain accessible and when you powered your computer off,
being stored will be permanently deleted. Ram can be attacked by Cold boot attack for more information you can get more from this source:
[Cold-Boot-Attack](https://en.wikipedia.org/wiki/Cold_boot_attack)


### Address Space
As I explained earlier that RAM is an array of memory cells without this powerful hardware component, we should not be able to work with computers. Ram has memory cells, each with its own physical memory used to access that cell. For the CPU to execute instructions and have access data stored in main memory,
it must specify a unique address for that data. We also already know that process has not direct access to physical memory because it can be harmful the operating system and even cause the crash completely which can be irritating.
Each process its own isolated address space, which is the predicatable because it solves the problem of security and isolation of processes from each other to OS.
To have better understanding of address space, let me overview a bit about virttual memory.
You can get more information from this source: [Address-Space](https://en.wikipedia.org/wiki/Address_space)



### Virtual Memory
I am not going to illustrate the usage of Virtual memory, but let me explain a bit about its skeleton. Virtual memory is a storage scheme that provides user an illusion of having a very big main memory.
Which means that, the abstraction is designed to seperate the logical memory that processes work with from physical memory.
I would like to say thet Virtual memory has a good usage by the OS because each process has its own virtual address space however, we ought not to forget that
the size of that space is depending on the hardware architecture. You can get more information from this source: 
[Virtual-Memory](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/ram-virtual-memory-pagefile-management)


### Paging
This one will be the last one of acquisition. As a short explanation shall be that the entire process address space is divided into blocks of fixed size. Paging provides the 
ability to virtualize the linear address space. It creates an execution environment in which a large linear address space is simulated.
We should not forget that the ```Memory Manager``` is responsible for unloading and also freeing physical memory.
The ```Memory Manager``` is important because it also translates virtual addresses into physical address with the help of hardware.
You can get more information from this source: [Memory-Paging](https://en.wikipedia.org/wiki/Memory_paging)



--> I am ready to get started with ````Rekall Framework``` We will firstly look at the source code and understanding what it does while perfoming memory analysis. Lets kick off.


# Rekall Memory Forensics
Now that we have understanding about Live memory forensics lets now talk about advanced memory forensics tool called `Rekall`.Rekall is a forensics Framework is a collection of memory to analyze memory dump. Rekall is written in Python and Its a fork of Volatility.

## Discover Rekall
As we are dealing with memory forensics it also important to meet rekall structure and plugins. We need to understand the functionality. Rekall is written in Python thus that means that we are able to read easily the source code.
For now you can use [Rekall-Github](https://github.com/google/rekall) but I should not recommend it. Morevover, you will be facing issues due to the python version.
For this purpose, I will be going to use `docker` its more flexible and more handy.

As I mentioned earlier, when you git your repo to you `/opt` which is recommended. We are now analyzing the structre of this Framework.

Go to `/memory-forensics/rekall/rekall-core/rekall` and use `ls -a` command to see what kind of pluging are written in this framework.

I am not going to analyze all files however, we will analyze `rekall.py`, and lets understand this advanced memory forensics Framework.


```

darkghost@malware:~/memory-forensics/rekall/rekall-core/rekall$ ls -al

total 428
drwxr-xr-x  4 root root  4096 Sep 22 02:38 .
drwxr-xr-x  4 root root  4096 Sep 22 02:38 ..
-rwxr-xr-x  1 root root 25287 Sep 22 02:38 addrspace.py
-rw-r--r--  1 root root  5118 Sep 22 02:38 addrspace_test.py
-rw-r--r--  1 root root  2477 Sep 22 02:38 algo.py
-rwxr-xr-x  1 root root 18477 Sep 22 02:38 args.py
-rw-r--r--  1 root root 11875 Sep 22 02:38 cache.py
-rw-r--r--  1 root root  1157 Sep 22 02:38 compatibility.py
-rwxr-xr-x  1 root root  9246 Sep 22 02:38 config.py
-rw-r--r--  1 root root  4381 Sep 22 02:38 constants.py
-rw-r--r--  1 root root   136 Sep 22 02:38 __init__.py
-rw-r--r--  1 root root  1420 Sep 22 02:38 interactive.py
-rw-r--r--  1 root root 21946 Sep 22 02:38 io_manager.py
-rw-r--r--  1 root root  2575 Sep 22 02:38 io_manager_test.py
-rwxr-xr-x  1 root root  9768 Sep 22 02:38 ipython_support.py
-rw-r--r--  1 root root  1698 Sep 22 02:38 kb.py
-rw-r--r--  1 root root 89894 Sep 22 02:38 obj.py
-rw-r--r--  1 root root  7247 Sep 22 02:38 obj_test.py
-rw-r--r--  1 root root 35722 Sep 22 02:38 plugin.py
drwxr-xr-x 13 root root  4096 Sep 22 02:38 plugins
-rw-r--r--  1 root root  3393 Sep 22 02:38 quotas.py
-rwxr-xr-x  1 root root  3579 Sep 22 02:38 rekal.py
-rw-r--r--  1 root root  2878 Sep 22 02:38 resources.py
-rw-r--r--  1 root root 23653 Sep 22 02:38 scan.py
-rw-r--r--  1 root root 47273 Sep 22 02:38 session.py
-rw-r--r--  1 root root  1767 Sep 22 02:38 session_test.py
-rw-r--r--  1 root root 14844 Sep 22 02:38 testlib.py
-rw-r--r--  1 root root   196 Sep 22 02:38 tests.py
-rw-r--r--  1 root root  2990 Sep 22 02:38 threadpool.py
-rw-r--r--  1 root root 12369 Sep 22 02:38 type_generator.py
drwxr-xr-x  2 root root  4096 Sep 22 02:38 ui
-rw-r--r--  1 root root  3377 Sep 22 02:38 _version.py


```

At this point, we will use `rekali.py` to have better understanding of this code.


```python


import logging
import pdb
import sys

import rekall
from rekall import args
from rekall import config
from rekall import constants
from rekall import plugin
from rekall import session
from rekall import quotas

from pkg_resources import iter_entry_points
for entry_point in iter_entry_points(group='rekall.plugins', name=None):
    entry_point.load()

# Load all the plugins.
from rekall import plugins  # pylint: disable=unused-import


config.DeclareOption(
    "--version", default=False, type="Boolean",
    help="Prints the Rekall version and exits.")


    name = "run"

    @classmethod
    def args(cls, parser):
        super(Run, cls).args(parser)
        parser.add_argument("script", default="print 'hello!'",
                            help="The script to evaluate")

        parser.add_argument("--run", default=None,
                            help="A file name to run.")

    def __init__(self, script, run=None, **kwargs):
        super(Run, self).__init__(**kwargs)
        if run is not None:
            script = open(run).read()

        exec(script, self.session.locals)


def main(argv=None):
    # New user interactive session (with extra bells and whistles).
    user_session = session.InteractiveSession()
    user_session.session_list.append(user_session)

    # Alow all special plugins to run.
    user_session.privileged = True

    def global_arg_cb(global_flags, _):
        if global_flags.version:
            print("This is Rekall Version %s (%s)" % (
                constants.VERSION, constants.CODENAME))

            print(rekall.get_versions())
            sys.exit(0)

    with user_session.GetRenderer().start():
        plugin_cls, flags = args.parse_args(
            argv=argv, global_arg_cb=global_arg_cb,
            user_session=user_session)

    # Install any quotas the user requested.
    user_session = quotas.wrap_session(user_session)
    try:
        # Run the plugin with plugin specific args.
        user_session.RunPlugin(plugin_cls, **config.RemoveGlobalOptions(flags))
    except Exception as e:
        logging.fatal("%s. Try --debug for more information." % e)
        if getattr(flags, "debug", None):
            pdb.post_mortem(sys.exc_info()[2])
        raise
    finally:
        user_session.Flush()

if __name__ == '__main__':
    main()

```

Well, we are interested in this part and lets view the source understandably.


```python
def main(argv=None):
    # New user interactive session (with extra bells and whistles).
    user_session = session.InteractiveSession()
    user_session.session_list.append(user_session)

    # Alow all special plugins to run.
    user_session.privileged = True

    def global_arg_cb(global_flags, _):
        if global_flags.version:
            print("This is Rekall Version %s (%s)" % (
                constants.VERSION, constants.CODENAME))

            print(rekall.get_versions())
            sys.exit(0)

    with user_session.GetRenderer().start():
        plugin_cls, flags = args.parse_args(
            argv=argv, global_arg_cb=global_arg_cb,
            user_session=user_session)


```

We are seeing that the user_session is interacting with session.py. I am going to analyze a bit about ````session.py```

```python

from rekall.ui import renderer
from rekall_lib import registry
from rekall_lib import utils


config.DeclareOption(
    "--repository_path", default=[], type="ArrayStringParser",
    help="Path to search for profiles. This can take "
    "any form supported by the IO Manager (e.g. zip files, "
    "directories, URLs etc)")



config.DeclareOption("-f", "--filename",
                     help="The raw image to load.")


config.DeclareOption(
    "--performance", default="normal", type="Choices",
    choices=["normal", "fast", "thorough"],
    help="Tune Rekall's choice of algorithms, depending on performance "
    "priority.")

LIVE_MODES = ["API", "Memory"]

```

We are checking ```session.py```, and immediately ```DeclareOption``` is being popped up. The session is quite simple it supports ```.zip, url, directory``` which is awesome.
My memory dump is ready to be thrown in this framework. Rekall allows us to use ```config.DeclareOption("-f", "--filename",help="The raw image to load.")``` like Volatility Framework however, Volatility does not allow me to use ```.mem``` I mean it does not
dump the memory. Overall i do like Volatility. It is quite simple to read and understand about this Framework as well. You can get more information from 
[Rekall-Github](https://github.com/google/rekall/blob/master/rekall-core/rekall/session.py) to have better understanding.


Most importantly, let me explain a bit about scanning ```memory files```. I am going to show you the source code of ```scan.py``` so that i can explain the code respectively

```python

from rekall import addrspace
from rekall import constants
from rekall_lib import registry
from rekall_lib import utils


class ScannerCheck(with_metaclass(registry.MetaclassRegistry, object)):
    """A scanner check is a special class which is invoked on an AS to check
    for a specific condition.

    The main method is def check(self, buffer_as, offset):
    This will return True if the condition is true or False otherwise.

    This class is the base class for all checks.
    """
    __abstract = True

    def __init__(self, profile=None, address_space=None, session=None,
                 **_kwargs):
        # The profile that this scanner check should use.
        self.profile = profile
        self.address_space = address_space
        self.session = session

    def object_offset(self, offset):
        return offset

    def check(self, buffer_as, offset):
        """Is the needle found at 'offset'?

        Arguments:
          buffer_as: An address space object with a chunk of data that can be
            checked for the needle.
        offset: The offset in the address space to check.
        """
        _ = offset
        _ = buffer_as
        return False

``` 


First of all, ı will not cover about ```profile``` yet because that will be my next topic that i want to cover. Lets overview this source and look at the code step by step. Its 
important that you ought to understand the structure of this code for being able to write your own code. As you can see we have ```profile, session, adress```
Of course, we need to specify our profile such that it will recognize windows machine and to be run properly. Address space, shall be important because, when we talk about address spacing we should consider that
there are few different categories of address spacing but let me cover about ```address space stack```. The main concept is about ```rekall``` but let me give a short demonstration about volatility plugins how it looks like.


As an example, we are considering ```Windows System``` crash dump with the architecture x64




```
Plugins // this reads the virtual address, which is requested by OS


After this process, it will go to AMD64PagedMemory

AMD64PagedMemory // this translates to physical memory address 


after this process, it will go to WindowsCrashDumpSpace 

WindowsCrashDumpSpace // this translates to file offset decompress (if it necessary)


after the last process, it will go to FileAddressSpace

FileAddressSpace // this will seek and read from file offset 
```




In this script I just wanted to illustrate what address space was and what it done. Let move to our main topic Rekall.  If you have understood this topic lets get started with ```profile mechanis```


## Profile Mechanism
AS I mentioned before that profile mechanism is the most important part of Rekall. In order to work with Memory forensics you have to be dealing with OS(operating system),
thus its necessary to specify your operating sytstem,being able to dump your memory to be analyzed it will be important.
Plugins are requesting virtual address from that dump. Rekall allows us to work with different operating system and processors which is of course predicatable.
Now that we already know why we using such profile mechanisms. Lets get started with using our memory dump. You can get your own memory through virtual or your main OS.


** I should say that, when i was trying to capture my own volatile memory i got a blue screen with windows error. You should be alerted. It can have to with your current CPU.**

```python

from rekall import plugin
from rekall.plugins.windows import common


class LoadWindowsProfile(common.AbstractWindowsCommandPlugin):
   

    name = "load_profile"

    interactive = True

    __args = [
        dict(name="module_name", positional=True, required=True,
             help="The name of the module (without the .pdb extensilon)."),

        dict(name="guid", help="The guid of the module.")
    ]

    def collect(self):
        if self.guid is None:
            # Try to detect the GUID automatically.
            module = self.session.address_resolver.GetModuleByName(
                self.module_name)
            if not module:
                raise plugin.PluginError(
                    "Unknown module %s." % self.module_name)

            profile_name = module.detect_profile_name()
            if not profile_name:
                raise plugin.PluginError(
                    "Unable to determine GUID for module %s." %
                    self.module_name)
        else:
            profile_name = "%s/GUID/%s" % (self.module_name, self.guid)

        profile = self.session.LoadProfile(profile_name)
        if profile == None:
            # Try to build it from the symbol serv
            profile = module.build_local_profile(profile_name, force=True)
            if profile == None:
                raise plugin.PluginError(
                    "Unable to fetch or build %s" % profile_name)

        if profile:
            module.profile = profile

        return []

```

I would like to explain by this code that profile is important because, you might be able to get a lot information from this memory. It does not matter
what you are using it can be Volatility or Rekall. You need to specify your own operating system. Whether you not do than it will not resolve your problem anc will have been an issue by investigating a memory.Lets focus on ```GUID```
As you can see that it is trying to detect ```GUID``` this term has a functionality such that
it identifies an object such as COM interface, or a COM class object, or a manager entry point.


```cpp

struct GUID{

unsigned long data1;
unsigned short data2;
unsigned short data3;
unsigned char data4[16];
}
```

Which data is declared in this struct. We need to know that a GUID is a 128-bit value consisting of one group 16 hexedecimal digits.
this code is important ```module = self.session.address_resolver.GetModuleByName(
                self.module_name)```


1.module is declared to self session address because we need to know the exact GUID
2. if not module, then it will be redirected to error regarding collecting GUID address



### Linux resolver 

```python
from builtins import str
__author__ = "Michael Cohen <scudette@gmail.com>"
from rekall import obj
from rekall.plugins.common import address_resolver
from rekall.plugins.linux import common



class LinuxAddressResolver(address_resolver.AddressResolverMixin,
                           common.LinuxPlugin):
    """A Linux specific address resolver plugin."""

    def _EnsureInitialized(self):
        if self._initialized:
            return

        # Insert a psuedo module for the kernel
        self.AddModule(KernelModule(session=self.session))

        # Add LKMs.
        for kmod in self.session.plugins.lsmod().get_module_list():
            self.AddModule(LKMModule(kmod, session=self.session))

        task = self.session.GetParameter("process_context")

        for vma in task.mm.mmap.walk_list("vm_next"):
            start = vma.vm_start
            end = vma.vm_end
            self.AddModule(MapModule(
                name="map_%#x" % start,
                start=start, end=end, session=self.session))

        self._initialized = True

```

This plugin is written for Linux OS and as you can understand from this source code that it looking for any kernel address of your ELF file to be recognized.


### Winndows resolver

```python

class WinAPIAddressResponse(address_resolver.AddressResolverMixin,
                            common.AbstractAPICommandPlugin):
    """Address resolver for windows API access."""

    @staticmethod
    def NormalizeModuleName(module_name):
        result = str(module_name)
        result = re.split(r"[/\\]", result)[-1]

        # Drop the file extension.
        result = result.split(".")[0]

        return result.lower()

    def _EnsureInitialized(self):
        """Initialize the address resolver.
        In windows we populate the virtual address space map from kernel modules
        and VAD mapped files (dlls).
        """
        if self._initialized:
            return

        try:
            process_context = self.session.GetParameter("process_context")
            if process_context != None:
                # Now use the vad.
                for vad in self.session.plugins.vad().merge_ranges(
                        process_context.pid):
                    self.AddModule(LiveModule(vad=vad, session=self.session))

        finally:
            self._initialized = True

```

 Here is the source/plugin for Windows OS. You can check it out. Here you can get more information about this plugin:
 
 [Windows-API](https://github.com/google/rekall/blob/master/rekall-core/rekall/plugins/response/windows.py)
 
 Everthing is abstracted and well explained. You can get also help from the internet. the purpose of this blog is telling you that Rekall has a lot cons.If you get any doubts, you can always ask us for any problem which you are facing with.
 Before analyzing a dump memory let me also explain about ```auto profile selection```
 I always recommned to forensics (investigators) please do not forget to practice and enhance your skills.
 Create your own memory dump file and look for any suspicious DLL and process injection.
 It will be awesome to create your own detection system.
 I hope that everything was clear and when you may not be able to read the source code well, please then check on internet or ask us.
 
 
 
 # Profile Auto Selection
 
 Lets remind us what profile was? Profile is where you place your operating system, architecture, version to give the information to the framework
 to analyze the your memory dump file. Now the most significant difference from volatility from the profile plugin, is that in rekall, the profile is in JSON format which makes us easily readable.
 For instance, Volatility represents a specific class defined within code based. Where Rekall represents such information in JSON format.
 
 Rekall has another cons, such as it can be hosted in public repository because those files are just data. Rekall will simply download necessary profile from the repository when you need it or required.
 Now when you do own deep research it seems that Rekall has a lot of capabilities. Lets see what Rekall has for us. 
 
 
```python

class PEImageFileDetector(DetectionMethod):

    name = "pe"
    order = 50

    def __init__(self, **kwargs):
        super(PEImageFileDetector, self).__init__(**kwargs)
        self.pe_profile = self.session.LoadProfile("pe")

    def Offsets(self):
        # We only care about the first offset in the file.
        return [0]

    def DetectFromHit(self, hit, _, address_space):
        # If the file is a PE file, we simply return the PE address space.
        if self.pe_profile._IMAGE_DOS_HEADER(vm=address_space).NTHeader:
            pe_as = pe_vtypes.PEFileAddressSpace(
                base=address_space, profile=self.pe_profile)

            self.session.kernel_address_space = pe_as
            self.session.SetCache("default_image_base", pe_as.image_base)

            machine_type = pe_as.nt_header.FileHeader.Machine
            if machine_type == "IMAGE_FILE_MACHINE_AMD64":
                self.pe_profile.set_metadata("arch", "AMD64")
            else:
                self.pe_profile.set_metadata("arch", "I386")

            return self.pe_profile

``` 

Firstly, we should understand that PE header string has been controlled by this plugin. If the PE is recognized by plugin then it will continue the process.

```python
if self.pe_profile._IMAGE_DOS_HEADER(vm=address_space).NTHeader:
            pe_as = pe_vtypes.PEFileAddressSpace(base=address_space, profile=self.pe_profile)
            
 ```
			`
`




**Note**

In order to understand this process **address space** should be reminded. 



**Address Space**

I am not going to fully explain about this term, but let me explain briefly. When this plugin recognizes the PE file, then it will redirect to address space of PE which will be accessed to data in RAM.
It handles virtual-to-physical-address translation when necessary, and transparently for difference in memory dump file formats.



You can check get more information [Guess-Profile](https://github.com/google/rekall/blob/master/rekall-core/rekall/plugins/guess_profile.py) 



Now view the source of DLLKernelImageDetector

```python

class WindowsKernelImageDetector(WindowsRSDSDetector):
    name = "windows_kernel_file"
    order = 50

    def Offsets(self):
        return [0]

    KERNEL_PATHS = [r"C:\Windows\SysNative\ntoskrnl.exe",
                    r"C:\Windows\System32\ntoskrnl.exe"]

    def DetectFromHit(self, hit, _, address_space):
        for potential_path in self.KERNEL_PATHS:
            # Try to make the kernel image into the address_space.
            image_offset = address_space.get_mapped_offset(potential_path, 0)

            if image_offset is not None:
                file_as = addrspace.RunBasedAddressSpace(
                    base=address_space, session=self.session)
                file_as.add_run(0, image_offset, 2**63)

                pe_file_as = pe_vtypes.PEFileAddressSpace(
                    base=file_as, session=self.session)

                pe_helper = pe_vtypes.PE(
                    session=self.session,
                    address_space=pe_file_as,
                    image_base=pe_file_as.image_base)

                rsds = pe_helper.RSDS
                self.session.logging.info(
                    "Found RSDS in kernel image: %s (%s)",
                    rsds.GUID_AGE, rsds.Filename)
                result = self._test_rsds(rsds)
                if result:
                    return result
```

# Memory Dump With Rekall

Yes, we are now able to inject a code to our process, and we will understand how Rekall powerful it is. Lets get started to download Rekall with Docker. I do not recommned you
to download Rekall to clone into `/opt` because you will be facing with python errors. To start off, you should consider to download `docker` to your machine or you can just login remotely.
You can get more information from [Rekall-Docker](https://hub.docker.com/r/remnux/rekall). You just pull yoır docker image and let run it.


```
PS C:\WINDOWS\system32> docker images
REPOSITORY               TAG       IMAGE ID       CREATED         SIZE
docker101tutorial        latest    6151c6cdd116   8 days ago      28.9MB
qilingframework/qiling   latest    620bc4d94151   2 weeks ago     389MB
alpine/git               latest    692618a0d74d   4 weeks ago     43.4MB
remnux/rekall            latest    0d2ed24e9d2a   11 months ago   925MB
PS C:\WINDOWS\system32>

```
As you can see Rekall has been installed. We do not forget to use ftk imager to capture your volatile memory because we are going to be able to inject the process and dump it in Rekall.

Well, i  will use windows 10 machine and we should understand `scan.py` once again.

```python
'_EPROCESS' : [None, {
        # Some standard fields for windows processes.
        'name': lambda x: x.ImageFileName,
        'pid': lambda x: x.UniqueProcessId,
        'dtb': lambda x: x.Pcb.DirectoryTableBase.v(),

        'CreateTime' : [None, ['WinFileTime', {}]],
        'ExitTime' : [None, ['WinFileTime', {}]],
        'InheritedFromUniqueProcessId' : [None, ['unsigned int']],
        'ImageFileName' : [None, ['String', dict(length=16)]],
        'UniqueProcessId' : [None, ['unsigned int']],
        'Session': [None, ["Pointer", dict(target="_MM_SESSION_SPACE")]],=-
        'Token': [None, ["_EX_FAST_REF", dict(target="_TOKEN")]],
        }],
```

We have Session which we talked before. UniqueProcessId, which will be important, because we will be deailng with process ID as well as ImageFileName.
PID, is defined as process ID for instance, if you want to inject `notepad.exe` that you can use process ID of notepad. Before diving into Rekall's memory forensics let me cover about
`DLL`. We are going to inject DLL and process to demonstrate how it looks like, but before it is important to have a knowledge about `DLL`.



## DLL (Dynamic-Link-library)

A DLL is available as a file on Windows with the .dll extension. Without DLL it is impossible to run an `.EXE`. A DLL file also uses the PE file format to describe its structure and content. Windows uses 
DLL file because it holds executable code and instructions. Its important to note that, if you double click an `EXE` file, it launches as a process.

```c


DLLfunction(x,y) // dll
{

 x = y + z;
 return x;

}
// program 1
int main() 
{
	numeric = DLLfunction(4,6);
}

// program 2

int main() 
{
	numeric = DLLfunction(4,6);
	printf("Value: %d",numeric);
}


```
As you can DLLfunction has two helpers to be run properly. We already know what Import table is, if you could not remember please check above for more information. A DLL is loaded into memory. We also already know
that an executable file depends on DLL for their APIs thus its important to note that Windows loader loads an executable PE file, which means that all DLLs dependencies into memory first.


**_Now lets get started to discover Rekall Framework_**


## Memory dump

Being able to run rekall, i had already mentioned about docker  which should be installed. You will be facing some issues if you try to run rekall from github repositories, there will be
dependencies errors.



```

C:\WINDOWS\system32> docker pull remnux/rekall
Using default tag: latest
latest: Pulling from remnux/rekall
7b1a6ab2e44d: Pull complete
958b3bb1d32e: Pull complete
ba8b47b35067: Pull complete
73d2e657e820: Pull complete
4f4fb700ef54: Pull complete
Digest: sha256:301664d32ebee20c8653ea137e414f938e6b717e1eebcf62cb8e690433cee627
Status: Downloaded newer image for remnux/rekall:latest
docker.io/remnux/rekall:latest

```

As you can see, I pulled remnux/rekall from docker.io. The next step is:


```

C:\WINDOWS\system32> docker images
REPOSITORY               TAG       IMAGE ID       CREATED         SIZE
docker/getting-started   latest    cb90f98fd791   5 months ago    28.8MB
remnux/rekall            latest    0d2ed24e9d2a   11 months ago   925MB

```

To see of the repository is being placed. The next is:

```

C:\WINDOWS\system32>docker ps
CONTAINER ID   IMAGE                    COMMAND                  CREATED         STATUS         PORTS                NAMES
b843c6cafa1e   docker/getting-started   "/docker-entrypoint.…"   7 minutes ago   Up 7 minutes   0.0.0.0:80->80/tcp   cranky_black

```

To see the process of this container. Now it is to use this command:


```

C:\WINDOWS\system32> docker exec -it b7c98db01e8c  bash
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.


```
Just specify your docker container and use: `docker exec -it b7c98db01e8c  bash`



If everything is OK! lets try to use `rekall -h` command



```
nonroot@b7c98db01e8c:~/files$ rekall -h
Webconsole disabled: cannot import name 'webconsole_plugin' from partially initialized module 'rekall.plugins.tools' (most likely due to a circular import) (/usr/local/lib/python3.8/dist-packages/rekall/plugins/tools/__init__.py)
usage: rekall [-p PROFILE] [-v] [-q] [--debug] [--output_style {concise,full}] [--logging_level {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [--log_domain [{PageTranslation} [{PageTranslation} ...]]] [--pager PAGER]
              [--paging_limit PAGING_LIMIT] [--colors {auto,yes,no}] [-F FORMAT] [--plugin [PLUGIN [PLUGIN ...]]] [-h] [--cache CACHE] [--cache_expiry_time CACHE_EXPIRY_TIME]
              [--repository_path [REPOSITORY_PATH [REPOSITORY_PATH ...]]] [-f FILENAME] [--buffer_size BUFFER_SIZE] [--output OUTPUT] [--max_collector_cost MAX_COLLECTOR_COST] [--home HOME]
              [--logging_format LOGGING_FORMAT] [--performance {normal,fast,thorough}] [--live LIVE] [--cpu_quota CPU_QUOTA] [--load_quota LOAD_QUOTA] [--dtb DTB] [--kernel_slide KERNEL_SLIDE] [-o FILE_OFFSET]
              [--ept EPT [EPT ...]] [--timezone TIMEZONE] [--cache_dir CACHE_DIR]
              [--highlighting_style {default,emacs,friendly,colorful,autumn,murphy,manni,material,monokai,perldoc,pastie,borland,trac,native,fruity,bw,vim,vs,tango,rrt,xcode,igor,paraiso-light,paraiso-dark,lovelace,algol,algol_nu,arduino,rainbow_dash,abap,solarized-dark,solarized-light,sas,stata,stata-light,stata-dark,inkpot,zenburn,gruvbox-dark,gruvbox-light}]
              [--name_resolution_strategies [{Module,Symbol,Export} [{Module,Symbol,Export} ...]]] [--autodetect_build_local_tracked [AUTODETECT_BUILD_LOCAL_TRACKED [AUTODETECT_BUILD_LOCAL_TRACKED ...]]]
              [--pagefile [PAGEFILE [PAGEFILE ...]]]
              [--autodetect {nt_index,pe,rsds,windows_kernel_file,linux_index,linux,osx,ntfs,tsk} [{nt_index,pe,rsds,windows_kernel_file,linux_index,linux,osx,ntfs,tsk} ...]]
              [--autodetect_threshold AUTODETECT_THRESHOLD] [--autodetect_build_local {full,basic,none}] [--autodetect_scan_length AUTODETECT_SCAN_LENGTH] [--agent_configuration AGENT_CONFIGURATION]
              [--version] [-]
			  
			  
```


So this means that everything is OK!






Being able to demonstrate `rekall` I am going go inject inject.dll to notepad to illustrate it properly



```

 Directory of C:\Users\Malwa\Desktop\Malware Dev\DLL\DLLinject\x64\Debug

09/29/2022  12:47 PM    <DIR>          .
09/29/2022  12:47 PM    <DIR>          ..
09/29/2022  12:48 PM            64,000 Rekall-DLL.exe
09/29/2022  12:48 PM         1,355,776 Rekall-DLL.pdb
               2 File(s)      1,419,776 bytes
               2 Dir(s)  133,399,515,136 bytes free

C:\Users\Malwa\Desktop\Malware Dev\DLL\DLLinject\x64\Debug>Rekall-DLL.exe 19608
Injecting DLL to PID: 19608





```


You should look at the process hacker or task manager to identify the PID. In my case was it 1652. Now we are going to be able to dump our volatile memory to be analyzed with 
Rekall Framework.





I am also going to disassamble this code with IDA to look at the process


```assembly


lea     rax, [rsp+5C8h+ProcessInformation]
mov     [rsp+5C8h+lpProcessInformation], rax ; lpProcessInformation
lea     rax, [rsp+5C8h+StartupInfo]
mov     [rsp+5C8h+lpStartupInfo], rax ; lpStartupInfo
mov     [rsp+5C8h+lpCurrentDirectory], 0 ; lpCurrentDirectory
mov     [rsp+5C8h+lpEnvironment], 0 ; lpEnvironment
mov     [rsp+5C8h+dwCreationFlags], 1000044h ; dwCreationFlags
mov     [rsp+5C8h+bInheritHandles], 1 ; bInheritHandles
xor     r9d, r9d        ; lpThreadAttributes
xor     r8d, r8d        ; lpProcessAttributes
lea     rdx, CommandLine ; "rundll32.exe"
xor     ecx, ecx        ; lpApplicationName
call    cs:CreateProcessA
mov     [rsp+5C8h+var_578], eax
cmp     [rsp+5C8h+var_578], 0
jnz     short loc_18000114C
                                                                                                                          

```


```assembly


lea     r8, [rbp+1C0h+dllPath] ; lpBuffer
mov     rdx, [rbp+1C0h+remoteBuffer] ; lpBaseAddress
mov     rcx, [rbp+1C0h+processHandle] ; hProcess
call    cs:__imp_WriteProcessMemory
lea     rcx, ModuleName ; "Kernel32"
call    cs:__imp_GetModuleHandleW
lea     rdx, ProcName   ; "LoadLibraryW"
mov     rcx, rax        ; hModule
call    cs:__imp_GetProcAddress
mov     [rbp+1C0h+threatStartRoutineAddress], rax
mov     [rsp+200h+lpThreadId], 0 ; lpThreadId
mov     [rsp+200h+dwCreationFlags], 0 ; dwCreationFlags
mov     rax, [rbp+1C0h+remoteBuffer]
mov     qword ptr [rsp+200h+flProtect], rax ; lpParameter
mov     r9, [rbp+1C0h+threatStartRoutineAddress] ; lpStartAddress
xor     r8d, r8d        ; dwStackSize
xor     edx, edx        ; lpThreadAttributes
mov     rcx, [rbp+1C0h+processHandle] ; hProcess
call    cs:__imp_CreateRemoteThread
mov     rcx, [rbp+1C0h+processHandle] ; hObject
call    cs:__imp_CloseHandle

```


Let me explain a bit about this piece of code.

`WriteProcessMemory` With the WriteProcessMemory function, we write the path of our dll file to the virtual address of the previously designed process.
`VirtualAllocEx` With the VirtualAllocEx function, we allocate space before we can write the path of our dll file to the virtual address space of the target process.
`GetProcAddress` With the  GetProcAddress function, we get the address on the memory of the LoadLibraryW function, which we will use to load our dll file to the target process. The LoadLibraryW function is a function of the kernel32.dll library.


Awesome. Now we are going to analyze with Rekall. First of all, you should have already dumped your volatile memory to your main OS or virtual machine to make it more easier.




1. be sure that your docker is running
2. when you dumped your file to the right directory
3. use this command `docker exec -it rekallcontainer bash`
4. Use this command `docker cp inject.mem rekallcontainer:/` 
5. after entering to your docker, you should use `cd ../../../../`
6. use `mv` command to /home/nonroot/files



Of course, we already know that PID of notepad 19608 lets analyze that 



```
[1] suspicious.mem 08:00:30> ldrmodules(19608)
       base      in_load in_init in_mem mapped
  -------------- ------- ------- ------ ------
--------------------------------
0xb70d37594180 Notepad.exe 19608
--------------------------------
  0x7ffafdc20000 True    True    True   C:\Windows\System32\propsys.dll
  0x7ffaee110000 True    True    True   C:\Windows\System32\winspool.drv
  0x7ffadce60000 True    True    True   C:\Windows\System32\Windows.UI.Xaml.Controls.dll
  0x7ffad4f70000 True    True    True   C:\Program Files\WindowsApps\microsoft.vclibs.140.00.uwpdesktop_14.0.30704.0_x64__8wekyb3d8bbwe\vcruntime140_1.dll
  0x7ffa91690000 True    True    True   C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2208.25.0_x64__8wekyb3d8bbwe\Notepad\NotepadXamlUI.dll
  0x7ff615230000 True    False   True   C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2208.25.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
  0x7ffa60750000 True    True    True   C:\Program Files\WindowsApps\microsoft.ui.xaml.2.8_8.2208.12001.0_x64__8wekyb3d8bbwe\Microsoft.UI.Xaml.dll
  0x7ffaa2400000 True    True    True   C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2208.25.0_x64__8wekyb3d8bbwe\msptls.dll
  0x7ffa91910000 True    True    True   C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2208.25.0_x64__8wekyb3d8bbwe\riched20.dll
  0x7ffa99e70000 True    True    True   C:\Windows\System32\efswrt.dll
  0x7ffac2750000 True    True    True   C:\Program Files\WindowsApps\microsoft.vclibs.140.00.uwpdesktop_14.0.30704.0_x64__8wekyb3d8bbwe\vcruntime140.dll
  0x7ffac26c0000 True    True    True   C:\Program Files\WindowsApps\microsoft.vclibs.140.00.uwpdesktop_14.0.30704.0_x64__8wekyb3d8bbwe\msvcp140.dll
  0x7ffad79e0000 True    True    True   C:\Program Files\WindowsApps\microsoft.vclibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe\vcruntime140_1_app.dll
  0x7ffad7930000 True    True    True   C:\Program Files\WindowsApps\microsoft.vclibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe\msvcp140_app.dll
  0x7ffad53a0000 True    True    True   C:\Windows\System32\msftedit.dll
  0x7ffad5370000 True    True    True   C:\Windows\System32\globinputhost.dll
  0x7ffad69f0000 True    True    True   C:\Windows\System32\UIAutomationCore.dll
  0x7ffad79c0000 True    True    True   C:\Program Files\WindowsApps\microsoft.vclibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe\vcruntime140_app.dll
  0x7ffadc0b0000 True    True    True   C:\Windows\System32\DataExchange.dll
  0x7ffad9390000 True    True    True   C:\Windows\System32\Windows.UI.Core.TextInput.dll
  0x7ffadc2c0000 True    True    True   C:\Windows\System32\threadpoolwinrt.dll





```


When we use ldrmodules(19608), You will see this output.It is also important to check `vad`

### What is VAD?

VAD is a tree structure and like any tree structure 
it has a root (which is called Vadroot) and nodes/leafs (Vadnodes) that contains all the information related to memory ranges
reserved for a specific process by the memory manager

source: [VAD](https://imphash.medium.com/windows-process-internals-a-few-concepts-to-know-before-jumping-on-memory-forensics-part-4-16c47b89e826)


We should consider where it has permissions. Let me cover about the permissions a bit.


```

PAGE_EXECUTE: Memory can be executed but cannot be written to
PAGE_EXECUTE_READ: Memory can be executed or read but cannot be written to
PAGE_EXECUTE_READWRITE: Memory can be executed, read and write.
PAGE_NOACCESS: No access to this memory region
PAGE_READONLY: Only read access to the memory
PAGE_READWRITE: Read, Write access to the memory but no execution.




```

These permissions give us an indication of the type of access. Lets analyze that with `vad()`


```


0xb70d3aa9a6c0   2 0x7ffaee110000 0x7ffaee1aafff      4 Mapped  Exe    EXECUTE_WRITECOPY    C:\Windows\System32\winspool.drv
0xb70d3aa7bb80   8 0x7ffaee1b0000 0x7ffaee218fff      4 Mapped  Exe    EXECUTE_WRITECOPY    C:\Windows\System32\oleacc.dll
0xb70d3aa9b160   7 0x7ffaee220000 0x7ffaee4c4fff      8 Mapped  Exe    EXECUTE_WRITECOPY    C:\Windows\WinSxS\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.22000.120_none_9d947278b86cc467\comctl32.dll
0xb70d3aa9f260   8 0x7ffaeecd0000 0x7ffaeecd5fff      3 Mapped  Exe    EXECUTE_WRITECOPY    C:\Users\Malwa\Desktop\Malwation\Rekall\dark.dll
0xb70d3aa9ba20   6 0x7ffaf0750000 0x7ffaf0850fff      6 Mapped  Exe    EXECUTE_WRITECOPY    C:\Windows\System32\MrmCoreR.dll
0xb70d3aa9e360   7 0x7ffaf3cc0000 0x7ffaf55bffff    157 Mapped  Exe    EXECUTE_WRITECOPY    C:\Windows\System32\DriverStore\FileRepository\u0357176.inf_amd64_828ff99cacd4aa89\B356563\atidxx64.dll
0xb70d3aa9b840   5 0x7ffaf68b0000 0x7ffaf68edfff      3 Mapped  Exe    EXECUTE_WRITECOPY    C:\Windows\System32\Windows.StateRepositoryClient.dll
0xb70d3aaa0de0   8 0x7ffaf71b0000 0x7ffaf71dcfff      4 Mapped  Exe    EXECUTE_WRITECOPY    C:\Windows\System32\D3DSCache.dll
0xb70d3aaa00c0   7 0x7ffaf7880000 0x7ffaf78aefff      4 Mapped  Exe    EXECUTE_WRITECOPY    C:\Windows\System32\amdihk64.dll
0xb70d3aa9eb80   6 0x7ffaf7930000 0x7ffaf7967fff      3 Mapped  Exe    EXECUTE_WRITECOPY    C:\Windows\System32\DriverStore\FileRepository\u0357176.inf_amd64_828ff99cacd4aa89\B356563\atiuxp64.dll
0xb70d3aa9ef40   7 0x7ffaf7a00000 0x7ffaf7bdafff     16 Mapped  Exe    EXECUTE_WRITECOPY    C:\Windows\System32\DriverStore\FileRepository\u0357176.inf_amd64_828ff99cacd4aa89\B356563\aticfx64.dll
0xb70d3aa9ce20   4 0x7ffaf8120000 0x7ffaf8935fff     18 Mapped  Exe    EXECUTE_WRITECOPY    C:\Windows\System32\OneCoreUAPCommonProxyStub.dll
0xb70d3aa9c420   6 0x7ffaf8c60000 0x7ffaf8ec5fff      7 Mapped  Exe    EXECUTE_WRITECOPY    C:\Windows\System32\twinapi.appcore.dll
0xb70d3aa9c600   5 0x7ffaf9650000 0x7ffaf966afff      3 Mapped  Exe    EXECUTE_WRITECOPY    C:\Windows\System32\Windows.StateRepositoryCore.dll



```

hmm.... `EXECUTE_WRITECOPY` seems interesting. APT would use hidden directory of course however, ı just want to demonstrate what kind of capabilities it has.




Enables execute, read-only, or copy-on-write access to a mapped view of a file mapping object. An attempt to write to a committed copy-on-write page results in a private copy of the page being made for the process. 
The private page is marked as PAGE_EXECUTE_READWRITE, and the change is written to the new page.


source : [Microsoft](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)

We can also use `pslist()` command to specify only the process


```

0xb70d3a9240c0 msedgewebview2       16344  17700            9            -          1 False  2022-10-01 09:02:35Z     -
0xb70d2cb04080 SystemSettings       16348   1344           14            -          1 False  2022-10-01 09:00:55Z     -
0xb70d32d570c0 firefox.exe          16428   2756            5            -          1 False  2022-10-01 09:19:08Z     -
0xb70d39b25080 vcpkgsrv.exe         16568  19320           10            -          1 True   2022-10-01 09:23:15Z     -
0xb70d31f230c0 conhost.exe          16680  16692            2            -          1 False  2022-10-01 09:01:00Z     -
0xb70d2bc70080 wsl.exe              16692  11088            2            -          1 False  2022-10-01 09:01:00Z     -
0xb70d32d92180 Telegram.exe         16768   4828           45            -          1 False  2022-10-01 09:05:16Z     -
0xb70d2e4bf180 FluentTerminal       16792   1344           39            -          1 False  2022-10-01 09:01:27Z     -
0xb70d31cd1180 dllhost.exe          16808   1344            4            -          1 False  2022-10-01 09:14:05Z     -
0xb70d2cf460c0 svchost.exe          16844   1124           11            -          0 False  2022-10-01 09:00:56Z     -
0xb70d318c10c0 dllhost.exe          16868   1344           16            -          1 False  2022-10-01 09:00:56Z     -
0xb70d3a7680c0 vmware-unity-h       17212   6072            3            -          1 True   2022-10-01 09:16:24Z     -
0xb70d31a0e080 docker.exe           17256  11088           16            -          1 False  2022-10-01 09:01:00Z     -
0xb70d2ad0a0c0 wslhost.exe          17332   5240            1            -          1 False  2022-10-01 09:00:57Z     -
0xb70d32e890c0 conhost.exe          17512  13856            4            -          1 False  2022-10-01 09:01:29Z     -
0xb70d32658080 wslhost.exe          17580   1424            1            -          1 False  2022-10-01 09:01:02Z     -
0xb70d3265b080 wslhost.exe          17588   4252            1            -          1 False  2022-10-01 09:01:02Z     -
0xb70d3265c080 wslhost.exe          17596  12908            1            -          1 False  2022-10-01 09:01:02Z     -
0xb70d3a9350c0 firefox.exe          17624   2756           33            -          1 False  2022-10-01 09:19:08Z     -
0xb70d3265f080 conhost.exe          17660  17580            3            -          1 False  2022-10-01 09:01:02Z     -
0xb70d32662080 conhost.exe          17680  17588            3            -          1 False  2022-10-01 09:01:02Z     -
0xb70d3a44b180 msedgewebview2       17700  15788           30            -          1 False  2022-10-01 09:02:35Z     -
0xb70d3265e080 conhost.exe          17704  17596            3            -          1 False  2022-10-01 09:01:02Z     -
0xb70d32d17100 MoNotification       18120   2272            4            -          1 False  2022-10-01 09:01:46Z     -
0xb70d2d6f1180 firefox.exe          18536   2756           27            -          1 False  2022-10-01 09:19:08Z     -
0xb70d396da0c0 ServiceHub.Hos       18600  15520           13            -          1 False  2022-10-01 09:22:24Z     -
0xb70d377e5080 vcpkgsrv.exe         18664   3572            7            -          1 True   2022-10-01 09:22:21Z     -
0xb70d3a8020c0 ServiceHub.Thr       18992    664           26            -          1 False  2022-10-01 09:23:11Z     -
0xb70d1dc32080 vcpkgsrv.exe         19080  19320           10            -          1 True   2022-10-01 09:23:15Z     -
0xb70d39b9e080 vshost.exe           19320  15208            1            -          1 False  2022-10-01 09:23:15Z     -
0xb70d2b5af180 dllhost.exe          19512   1344            6            -          1 False  2022-10-01 09:28:08Z     -
0xb70d37594180 Notepad.exe          19608   4828           19            -          1 False  2022-10-01 09:27:01Z     -
0xb70d378dd180 firefox.exe          20032   2756           12            -          1 False  2022-10-01 09:24:09Z     -
0xb70d3a76e180 MSBuild.exe          20568  15208            8            -          1 False  2022-10-01 09:26:23Z     -
0xb70d39e9b0c0 vcpkgsrv.exe         20608  19320            9            -          1 True   2022-10-01 09:23:35Z     -
0xb70d39ae80c0 ServiceHub.Hos       20812    664           22            -          1 False  2022-10-01 09:23:36Z     -
0xb70d3a6ae180 ServiceHub.Tes       21196    664           14            -          1 False  2022-10-01 09:23:39Z     -
0xb70d3acbd0c0 audiodg.exe          21660   4120            6            -          0 False  2022-10-01 09:26:26Z     -
0xb70d2af4d080 WinRAR.exe           22796   6608            9            -          1 False  2022-10-01 09:28:09Z     -
0xb70d2b180180 wsl.exe              23084  12072            0            -          0 False  2022-10-01 09:28:49Z     2022-10-01 09:28:49Z
0xb70d39b680c0 firefox.exe          24048   2756           12            -          1 False  2022-10-01 09:24:19Z     -
0xb70d32cbd180 conhost.exe          24476  20568            2            -          1 False  2022-10-01 09:26:23Z     -
Out<06:49:07> Plugin: pslist (WinPsList)



```

After this we can use regex method to find our malicios exe file.



```

[1] suspicious.mem 06:49:39> pslist(proc_regex="notepad")
  _EPROCESS            name          pid   ppid  thread_count handle_count session_id wow64    process_create_time       process_exit_time
-------------- -------------------- ----- ------ ------------ ------------ ---------- ------ ------------------------ ------------------------
0xb70d37594180 Notepad.exe          19608   4828           19            -          1 False  2022-10-01 09:27:01Z     -




```
Use this command: `pslist(proc_regex="notepad")` to filter malicious .exe



We can also dump DLL files with `dlldump(proc_regex = "notepad")`
```




0xb70d37594180 Notepad.exe 19608 0x7ffafbcc0000 CoreUIComponents.dll module.19608.3a0394180.7ffafbcc0000.CoreUIComponents.dll
0xb70d37594180 Notepad.exe 19608 0x7ffa99e70000 efswrt.dll           module.19608.3a0394180.7ffa99e70000.efswrt.dll
0xb70d37594180 Notepad.exe 19608 0x7ffaee1b0000 oleacc.dll           module.19608.3a0394180.7ffaee1b0000.oleacc.dll
0xb70d37594180 Notepad.exe 19608 0x7ffaea090000 Windows.ApplicationM module.19608.3a0394180.7ffaea090000.Windows.ApplicationModel.dll
                                                odel.dll
0xb70d37594180 Notepad.exe 19608 0x7ffaddf40000 directmanipulation.d module.19608.3a0394180.7ffaddf40000.directmanipulation.dll
                                                ll
0xb70d37594180 Notepad.exe 19608 0x7ffaf9ab0000 windowscodecs.dll    module.19608.3a0394180.7ffaf9ab0000.windowscodecs.dll
0xb70d37594180 Notepad.exe 19608 0x7ffaf9710000 wuceffects.dll       module.19608.3a0394180.7ffaf9710000.wuceffects.dll
0xb70d37594180 Notepad.exe 19608 0x7ffb01020000 bcrypt.dll           module.19608.3a0394180.7ffb01020000.bcrypt.dll
0xb70d37594180 Notepad.exe 19608 0x7ffae0030000 twinapi.dll          module.19608.3a0394180.7ffae0030000.twinapi.dll
0xb70d37594180 Notepad.exe 19608 0x7ffaeecd0000 dark.dll             module.19608.3a0394180.7ffaeecd0000.dark.dll     <---------
0xb70d37594180 Notepad.exe 19608 0x7ffaea2c0000 daxexec.dll          module.19608.3a0394180.7ffaea2c0000.daxexec.dll
0xb70d37594180 Notepad.exe 19608 0x7ffaeb3f0000 container.dll        module.19608.3a0394180.7ffaeb3f0000.container.dll



```



We can also use `threads()` to specify  win32_start_symb


```

0xb70d2c672080  19608  23536 0x7ffb04164830 ntdll!RtlUserThreadStart       Notepad.exe      0x7ff615275e28 notepad+0x45e28
0xb70d2ea50080  19608  11052 0x7ffb04164830 ntdll!RtlUserThreadStart       Notepad.exe      0x7ffb04176a00 ntdll!TppWorkerThread
0xb70d37ded080  19608  23532 0xe687b90ab870 0xe687b90ab870                 Notepad.exe      0x7ffaf077fff0 mrmcorer!GetStringValueForManifestField+0x69e00xb70d2d671080  19608  10404 0x7ffb04164830 ntdll!RtlUserThreadStart       Notepad.exe      0x7ffb04176a00 ntdll!TppWorkerThread
0xb70d2b0c1080  19608  16860 0x7ffb04164830 ntdll!RtlUserThreadStart       Notepad.exe      0x7ffb0216f760 combase!CoTaskMemRealloc+0x870
0xb70d2acaf080  19608  17924 0x7ffb04164830 ntdll!RtlUserThreadStart       Notepad.exe      0x7ffb04176a00 ntdll!TppWorkerThread
0xb70d2af3c080  19608   7376 0x7ffb04164830 ntdll!RtlUserThreadStart       Notepad.exe      0x7ffb02451160 shcore!SHQueryValueExW+0x970
0xb70d20f1b080  19608   1804 0x7ffb04164830 ntdll!RtlUserThreadStart       Notepad.exe      0x7ffadf1b9e70 windows!DllCanUnloadNow+0x2f70
0xb70d2ded0080  19608   7656 0x7ffb04164830 ntdll!RtlUserThreadStart       Notepad.exe      0x7ffaf4711344 atidxx64!AmdLiquidVrD3D11WrapDeviceContext+0xa9014
0xb70d393e3080  19608  11704 0x7ffb04164830 ntdll!RtlUserThreadStart       Notepad.exe      0x7ffb0216f760 combase!CoTaskMemRealloc+0x870
0xb70d31620080  19608   6020 0x7ffb04164830 ntdll!RtlUserThreadStart       Notepad.exe      0x7ffaddf55410 directmanipulation+0x15410
0xb70d390c3080  19608  12484 0x7ffb04164830 ntdll!RtlUserThreadStart       Notepad.exe      0x7ffb04176a00 ntdll!TppWorkerThread
0xb70d2d9e0080  19608  10476 0x7ffb04164830 ntdll!RtlUserThreadStart       Notepad.exe      0x7ffaf4711344 atidxx64!AmdLiquidVrD3D11WrapDeviceContext+0xa9014
0xb70d2e45f080  19608  13692 0x7ffb04164830 ntdll!RtlUserThreadStart       Notepad.exe      0x7ffaf78844b0 amdihk64!Terminate+0x1520
0xb70d39087080  19608  21156 0x7ffb04164830 ntdll!RtlUserThreadStart       Notepad.exe      0x7ffaf7885760 amdihk64!Terminate+0x27d0
0xb70d39176080  19608   4040 0x7ffb04164830 ntdll!RtlUserThreadStart       Notepad.exe      0x7ffb02451160 shcore!SHQueryValueExW+0x970
0xb70d324cd080  19608  16368 0x7ffb04164830 ntdll!RtlUserThreadStart       Notepad.exe      0x7ffb02451160 shcore!SHQueryValueExW+0x970
0xb70d39070080  19608  21776 0x7ffb04164830 ntdll!RtlUserThreadStart       Notepad.exe      0x7ffb02451160 shcore!SHQueryValueExW+0x970
0xb70d2aa84080  19608  23156 0x7ffb04164830 ntdll!RtlUserThreadStart       Notepad.exe      0x7ffb02451160 shcore!SHQueryValueExW+0x970
0xb70d393cd080  19608  15556 0x7ffb04164830 ntdll!RtlUserThreadStart       Notepad.exe      0x7ffb02451160 shcore!SHQueryValueExW+0x970



```
As you see can it will be very useful to use `regex_proc` So far, we were talking about useful commands in Rekall terminal. Now let me write a simple how we can detect `Notepad`with Rekall plugins.







# Process Injection Detector Script

In order to write a correct script, we should be able to use Rekall's plugins. Before diving into our script
let me explain about this piece of code below:

```

yield dict(_ETHREAD=thread,
           pid=thread.Cid.UniqueProcess,
           tid=thread.Cid.UniqueThread,
           start=thread.StartAddress,
           start_symbol=utils.FormattedAddress(
               self.session.address_resolver,
               thread.StartAddress),
           Process=task.ImageFileName,
           win32_start=thread.Win32StartAddress,
           win32_start_symb=utils.FormattedAddress(
               self.session.address_resolver,
               thread.Win32StartAddress))



```
First of all, we are going to be able to use `pid` and `win32_start_symb` to analyze our malicious process.




Here is the code. Do not worry I will explain my code step by step. 






## Automated Python script for Rekall

You can check my script: [DLLProcessDetector.py](https://github.com/DarkGhost010/MemoryForensics-Rekall)

```python

# Telegram : @Black_Mamba010
# Twitter :  @DarkGhost
# Instagram: @d4rkc0d3r
dll_inject = []

def process():
    procs = session.plugins.pslist()
    for eprocess in procs.filter_processes():
        if(eprocess.name == "lsass.exe"):
            continue
        if(eprocess.name == "Notepad.exe"):
            if(vad(eprocess)):
                thread(eprocess.UniqueProcessId)


def vad(sample):
    a = True
    b = False
    vad_list = session.plugins.vad().collect_vadroot(sample.RealVadRoot, sample)
    if(len(vad_list) < 0):
        return b
    for s in vad_list:
        if(s['type'] == "Mapped" and s['protect'] == "EXECUTE_WRITECOPY" and s['filename'] != None):
            return a


def thread(pid):
     t = session.plugins.threads(pid)
     for k in t:
       if("kernel32!LoadLibraryW" in str(k["win32_start_symb"])):
                    dll_inject.append(pid)
                    break
     try:
        if(len(dll_inject) > 0):
            print("\t")
            for pid in dll_inject:
             print("Notepad has been infected  (PID: %d) " % (pid))
        else:
            print("Notepad has not been infected")
     except Exception as p:
        print(p)
                 
   

        
if __name__ == "__main__":
    process()


```
 
 
### def process() 

First of all, as we seen earlier that we need to dump `process list` because we already knew that we put our malicious DLL to `Notepad.exe`
but we have a problem. We know that the target is `Notepad` but as you can see in my code,if `lsass` in the process, please continue
because it gives us some issues on Windows 11. Lsass, Local Security Authority Server Service (LSASS) is a process in Microsoft Windows operating systems that is responsible for enforcing the security policy.

if `Notepad` in the process then, send it to `vad` (virtual address Descriptor).

### def vad()

Virtual address descriptor, this will be useful because it will give us the information about;

DLL files, memory protection, type, and more... so we parsed Notepad to `vad`. You can also check it via Rekall framework simultaneously.


if the given statements is true then, we will get `True` from that function. This means we can get the UniqueProcessId from that process.


### def thread()

kernel32!LoadLibraryW, Loads the specified module into the address space of the calling process. The specified module may cause other modules to be loaded.
It will be very handy, if we can identify that this process uses kernel32.dll after being executed.
If that is correct, and we are able to catch `kernel32.dll` then it will be placed in our `dll_inject` we are appending.

Lastly, we will  print the result.






#### Output of my script

```


[1] suspicious.mem 06:47:54> run -i DLLProcessDetect.py

Notepad has been infected  (PID: 19608) 



```



# Summary 

If you did like this memory Forensics with Rekall blog-post, please then not forget to share and like this blog. More awesome reverse and malware blogs will be appeared in this blog-site.
If you unable to understand this concept, feel free to ask us for help.

Thank you for reading this blog.

Ahmet Göker 


![image](https://user-images.githubusercontent.com/95978207/193447331-62ca0d8c-c440-44f4-b1d0-db3052a8e61b.png)





