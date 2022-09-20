---
layout: post
title: Ram Image Analysis and Automation
date: 2022-09-20 13:58:02 +0300
description: We do Ram Image analysis and automate it.
author: Utku Çorbacı
comments: true
tags: [Malware Analysis, Forensics, EN]
---

_“Teachers are the one and only people who save nations.”_
-- **Mustafa Kemal Atatürk**

Greetings; in this blog, we will automate this process after analyzing process injection techniques with **rekall**.

Firstly, we will talk about how to dump of an ram.

All plugins written are in this [repo](https://github.com/polynomen/rekall-plugins)

# Table Of Contents
<pre>
1. RAM Image Analysis Tool Structure
    1.1 Memory Layer
    1.2 Templates and Objects
2. Rekall Codebase Analysis
    2.1 Entry Point of Rekall and Constants
    2.2 Profile Mechanism
        2.2.1 Auto Profile Selection
    2.3 Memory Dump File Parser
        2.3.1 Session Manager
        2.3.2 Scanner
3. Manual Mem File Analysis With Rekall
    3.1 DLL Injection Detector Script
    3.2 Process Hollowing Detector Script
</pre>

# RAM Image Analysis Tools Structure
I will review the [volatility3](https://github.com/volatilityfoundation/volatility3) project to explain the file structure. According to Volatility, ram image analysis consists of 3 parts.

1. **Memory Layer**: Body of data that can be accessed by requesting data at a specific address
2. **Templates and Objects** : Interpreting the memory area according to the operating system profile and storing it as an object
3. **Symbols** : Structures of compiled applications

The point I want to make special mention here is **Templates and Objects**.

## Memory Layer
Memory (RAM), which is provided as a physical hardware, is designed as an area that can be used by applications and all services running on the operating system.

In this section, we will talk about how Windows manage memory. Windows memory manager has two responsibilities:

1. Translating, or mapping, a process’s virtual address space into physical memory so that when a thread running in the context of that process reads or writes to the virtual address space, the correct physical address is referenced.
2. _Actually, this is the point I'm going to make._ Paging some of the contents of memory to disk when it becomes overcommitted —that is, when running threads or system code try to use more physical memory than is currently available— and bringing the contents back into physical memory when needed.

The memory manager is part of Windows kernel and therefore exist in ntoskrnl.exe 

Components: 

- A set of executive system services for allocating, deallocating, and managing virtual memory, most of which are exposed through the Windows API or kernel-mode device driver interfaces
- A translation-not-valid and access fault trap handler for resolving hardware-detected memory management exceptions and making virtual pages resident on behalf of a process

Okay, now let's look at the memory layer in the Volatility project.
Memory layer is accessible for 

Since the main topic of the article is not Windows Internals, I don't go too deep. I will do that in a different post.
In the rest of the article, we will talk about how this memory structure is interpreted and stored by volatility and rekall.

> For more information about memory or another topic, you can check out [rekall page](http://memory-analysis.rekall-forensic.com).

## Templates and Objects
The file starts to be read and certain structures must be interpreted according to the operating system profile. In this case, we must define the operating system-specific structures and turn them into _"useful"_ objects. For example we can use [this link](https://codemachine.com/articles/kernel_structures.html) for interpreting windows specified structures.

Volatility codes about this:

path: `volatility3\framework\symbols\windows\__init__.py`

{% highlight python %}
class WindowsKernelIntermedSymbols(intermed.IntermediateSymbolTable):

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # Set-up windows specific types
        self.set_type_class('_ETHREAD', extensions.ETHREAD)
        self.set_type_class('_KTHREAD', extensions.KTHREAD)
        self.set_type_class('_LIST_ENTRY', extensions.LIST_ENTRY)
        self.set_type_class('_EPROCESS', extensions.EPROCESS)
        self.set_type_class('_UNICODE_STRING', extensions.UNICODE_STRING)
        self.set_type_class('_EX_FAST_REF', extensions.EX_FAST_REF)
        self.set_type_class('_TOKEN', extensions.TOKEN)
        self.set_type_class('_OBJECT_HEADER', pool.OBJECT_HEADER)
        self.set_type_class('_FILE_OBJECT', extensions.FILE_OBJECT)
        self.set_type_class('_DEVICE_OBJECT', extensions.DEVICE_OBJECT)
        self.set_type_class('_CM_KEY_BODY', registry.CM_KEY_BODY)
        self.set_type_class('_CMHIVE', registry.CMHIVE)
        self.set_type_class('_CM_KEY_NODE', registry.CM_KEY_NODE)
        self.set_type_class('_CM_KEY_VALUE', registry.CM_KEY_VALUE)
        self.set_type_class('_HMAP_ENTRY', registry.HMAP_ENTRY)
        self.set_type_class('_MMVAD_SHORT', extensions.MMVAD_SHORT)
        self.set_type_class('_MMVAD', extensions.MMVAD)
        self.set_type_class('_KSYSTEM_TIME', extensions.KSYSTEM_TIME)
        self.set_type_class('_KMUTANT', extensions.KMUTANT)
        self.set_type_class('_DRIVER_OBJECT', extensions.DRIVER_OBJECT)
        self.set_type_class('_OBJECT_SYMBOLIC_LINK', extensions.OBJECT_SYMBOLIC_LINK)
        self.set_type_class('_CONTROL_AREA', extensions.CONTROL_AREA)
        self.set_type_class('_SHARED_CACHE_MAP', extensions.SHARED_CACHE_MAP)
        self.set_type_class('_VACB', extensions.VACB)
        self.set_type_class('_POOL_TRACKER_BIG_PAGES', pool.POOL_TRACKER_BIG_PAGES)
        self.set_type_class('_IMAGE_DOS_HEADER', pe.IMAGE_DOS_HEADER)
        # Might not necessarily defined in every version of windows
        self.optional_set_type_class('_IMAGE_NT_HEADERS', pe.IMAGE_NT_HEADERS)
        self.optional_set_type_class('_IMAGE_NT_HEADERS64', pe.IMAGE_NT_HEADERS)
        # (.....)
{% endhighlight %}

There are processor profiles as well as operating system profiles. Let's take a look at _Intel_ for example. Actually we should talk about _"memory structure"_ before look at Intel implementation layer. 


# Rekall Codebase Analysis
Rekall is a memory analysis framework. It is a fork of Volatility and written in Python. I will review the codebase of Rekall to explain the file structure.
We're going to start with the rekall-core folder. Because the name is very attractive :) 
The directory structure is as follows:
```
rekall-core
rekall-core\rekall
rekall-core\rekall\plugins
rekall-core\rekall\ui
rekall-core\rekall\__init__.py
rekall-core\rekall\_version.py
rekall-core\rekall\addrspace_test.py
rekall-core\rekall\addrspace.py
rekall-core\rekall\algo.py
rekall-core\rekall\args.py
rekall-core\rekall\cache.py
rekall-core\rekall\compatibility.py
rekall-core\rekall\config.py
rekall-core\rekall\constants.py
rekall-core\rekall\interactive.py
rekall-core\rekall\io_manager_test.py
rekall-core\rekall\io_manager.py
rekall-core\rekall\ipython_support.py
rekall-core\rekall\kb.py
rekall-core\rekall\obj_test.py
rekall-core\rekall\obj.py
rekall-core\rekall\plugin.py
rekall-core\rekall\quotas.py
rekall-core\rekall\rekal.py
rekall-core\rekall\resources.py
rekall-core\rekall\scan.py
rekall-core\rekall\session_test.py
rekall-core\rekall\session.py
rekall-core\rekall\testlib.py
rekall-core\rekall\tests.py
rekall-core\rekall\threadpool.py
rekall-core\rekall\type_generator.py
rekall-core\resources
rekall-core\.gitattributes
rekall-core\MANIFEST.in
rekall-core\README.rst
rekall-core\setup.py
```

First of all, I will not analyze some of the files in the folder as we can know what they do by their name.

## Entry Point of Rekall and Constants
Since there is nothing interesting in the main file, I switch to the folder named rekall. The file named `rekal.py` seems to be the entry point of the main project, so I will start with it.

{% highlight python %}
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
{% endhighlight %}

Starting interactive session, parsing arguments and run plugins... What we see as constants is the constants.py file. This is the source of the profiles and the messages shown to the user, which we will talk about later.

{% highlight python %}
# (........)
VERSION = _version.get_versions()["pep440"]
CODENAME = _version.get_versions()["codename"]
SCAN_BLOCKSIZE = 1024 * 1024 * 10

# Official profile repository locations. We create the initial .rekallrc from
# this list.
PROFILE_REPOSITORIES = [
    u"https://github.com/google/rekall-profiles/raw/master",
    u"http://profiles.rekall-forensic.com",
]

# Deprecated URLs that don't work any more.
OLD_DEPRECATED_URLS = [
    u"https://raw.githubusercontent.com/google/rekall-profiles/master"
]

# (........)
{% endhighlight %}

One of the operations the entry point performs is an argument parser. Plugins are also loaded in this parser. 

This function:
{% highlight python %}
def parse_args(argv=None, user_session=None, global_arg_cb=None):
    """Parse the args from the command line argv.

    Args:
      argv: The args to process.
      user_session: The session we work with.
      global_arg_cb: A callback that will be used to process global
         args. Global args are those which affect the state of the
         Rekall framework and must be processed prior to any plugin
         specific args. In essence these flags control which plugins
         can be available.
    """
{% endhighlight %}


After parse, the LoadPlugin function is executed and all python files in the plugins file are imported.

{% highlight python %}
# (........)
if user_session.state.plugin:
      LoadPlugins(user_session.state.plugin)
      # External files might have introduced new plugins - rebuild the plugin
      # DB.
      user_session.plugins.plugin_db.Rebuild()
{% endhighlight %}

## Profile Mechanism
The profile mechanism is the most important part of Rekall. The profile mechanism is the part that allows Rekall to work with different operating systems and processors. In this section, firstly we should talk about what distinguishes Volatile from Rekall. Rekall was created to: increase documentation, improve code readability, performance improvements and simplify the magic^^ profile structure.
For example, in Volatility one must specify the profile before analysis begins:

`$ vol.py -f myimage.dd --profile Win7SP1x86 pslist`

Rekall's innovations on the profile mechanism are very attractive. He converted the profile files that Volatility stored in hard-to-read code into JSON format. In addition, it also introduced the process of automatically finding the profile of a given memory file.
We need special profile files to make sense of the memory file we have. This is because the memory file changes on different processors and even operating systems. 

(rekall-core\rekall\plugins\tools\json_tools.py)

> By the way, the plugin in this path (rekall-core\rekall\plugins\tools\profile_tool.py ) is used to implement the profile created by volatility into rekall.

Let's take an example.\
The processor reads and makes sense of the data according to a certain rule, starting at the desired address. Compilers that want to translate the written application into executable form must follow this rule. For example, in the C programming language one can define a struct which specifies how variables are laid out in memory.

{% highlight c %}
struct mystruct {
    int a;
    int b;
    int c;
};
{% endhighlight %}

The compiler use only the data that the user writes and organize the memory accordingly. But software like Rekall sees the data as gibberish, so it needs to know where the data is located. If we run this C software on the debugger, we can understand that the debugger also needs some data. In order to present this data to the user, the debugger needs to make sense of the data in memory. Compilers generate PDB data (information about what resides where) to facilitate debugging. This makes it easier for debuggers. 

Let's go to the [link](https://github.com/google/rekall-profiles) in the constants file to browse the sample profiles.

`rekall-profiles/v1.0/nt/eprocess_index.gz`
This path is the profile of the _EPROCESS_ structure in windows.

```
{
 "$INDEX": {
  "nt/GUID/0018A9A7F0334E8D965F310D1653A5452": {
   "GUID_AGE": "0018A9A7F0334E8D965F310D1653A5455", 
   "PDBFile": "0018A9A7F0334E8D965F310D1653A5452.pdb", 
   "ProfileClass": "Nt", 
   "Timestamp": "2011-06-23 02:27:31Z", 
   "Type": "Profile", 
   "Version": 20000404, 
   "arch": "I386", 
   "offsets": {
    "_EPROCESS.ImageFileName": 364, 
    "_EPROCESS.Pcb": 0, 
    "_KPROCESS.DirectoryTableBase": 24
   }
  }, 
  "nt/GUID/00625D7D36754CBEBA4533BA9A0F3FE22": {
   "GUID_AGE": "00625D7D36754CBEBA4533BA9A0F3FE25", 
   "PDBFile": "00625D7D36754CBEBA4533BA9A0F3FE22.pdb", 
   "ProfileClass": "Nt", 
   "Timestamp": "2010-11-20 08:44:05+0000", 
   "Type": "Profile", 
   "Version": 20000404, 
   "arch": "I386", 
   "offsets": {
    "_EPROCESS.ImageFileName": 364, 
    "_EPROCESS.Pcb": 0, 
    "_KPROCESS.DirectoryTableBase": 24
   }
  }, 
.....................
```

Well, we know that even now there are thousands of profiles. Are we going to make them all by hand? No, we don't. Moreover, we need to change profiles as operating system components change. The type_generator.py file in Rekall automatically does this for us by disassembling the code.
It performs the operation using the disassemble engine (Capstone) on this path (_rekall-core\rekall\plugins\tools\disassembler.py_).

### Auto Profile Selection
In this section we will explain how the automatic profile selection plugin works. It's actually very simple and clever :D
This is the file we will examine: `rekall-core\rekall\plugins\guess_profile.py`

Its main purpose is to search for structures or strings inside using heuristics. For example, if it is a file with a Windows image, the strings it will contain are known. `svchost.exe, csrss.exe or PE Headers`

This is the codes are pe header strings:
{% highlight python %}
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
{% endhighlight %}

What it does is very simple. But I will add kernel image search for tl;dr.

{% highlight python %}
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
{% endhighlight %}

## Memory Dump File Parser
### Session Manager
Since events in Rekall are executed over sessions, I will examine `sessions.py` file. What we have just mentioned: Profile selection, file argument, Plugin Container and many other settings are loaded here.

{% highlight python %}
class Session(with_metaclass(registry.MetaclassRegistry, object)):
    """Base session.

    This session contains the bare minimum to use rekall.
    """

    SERIALIZABLE_STATE_PARAMETERS = [
        ("ept", u"IntParser"),
        ("profile", u"FileName"),
        ("filename", u"FileName"),
        ("pagefile", u"FileName"),
        ("session_name", u"String"),
        ("timezone", u"TimeZone"),
    ]

    # The currently active address resolver.
    _address_resolver = None

    # Each session has a unique session id (within this process). The ID is only
    # unique among the sessions currently active.
    session_id = 0

    # Privileged sessions are allowed to run dangerous plugins.
    privileged = False

    def __init__(self, **kwargs):
        self.progress = ProgressDispatcher()

        # Cache the profiles we get from LoadProfile() below.
        self.profile_cache = {}

        # A container for active plugins. This is done so that the interactive
        # console can see which plugins are active by simply command completing
        # on this object.
        self.plugins = PluginContainer(self)

        # When the session switches process context we store various things in
        # this cache, so we can restore the context quickly. The cache is
        # indexed by the current process_context which can be found from
        # session.GetParameter("process_context").
        self.context_cache = {}
        self._repository_managers = []

        # Store user configurable attributes here. These will be read/written to
        # the configuration file.
        self.state = Configuration(session=self)
        self.cache = cache.Factory(self, "memory")
        with self.state:
            for k, v in list(kwargs.items()):
                self.state.Set(k, v)

        # We use this logger if provided.
        self.logger = kwargs.pop("logger", None)
        self._logger = None

        # Make this session id unique.
        Session.session_id += 1

        # At the start we haven't run any plugin.
        self.last = None

        # Locks for running hooks.
        self._hook_locks = set()

        # Hooks that will be called when we get flushed.
        self._flush_hooks = []
        self.renderers = []
{% endhighlight %}

Address Resolver:

{% highlight python %}
    @utils.safe_property
    def address_resolver(self):
        """A convenience accessor for the address resolver implementation.

        Note that the correct address resolver implementation depends on the
        profile. For example, windows has its own address resolver, while Linux
        and OSX have a different one.
        """
        # Get the current process context.
        current_context = (self.GetParameter("process_context").obj_offset or
                           "Kernel")

        # Get the resolver from the cache.
        address_resolver = self.context_cache.get(current_context)
        if address_resolver == None:
            # Make a new address resolver.
            address_resolver = self.plugins.address_resolver()
            self.context_cache[current_context] = address_resolver

        return address_resolver
{% endhighlight %}

### Scanner
We can also examine a sample pe scanner for how any scanner works, but rekall is enough for this article. For example, if we want to read the `_EPROCESS` structure from memory, we need to know about the whole structure. This structure is defined in rekall because it's special.

`rekall-core\rekall\plugins\overlays\windows\common.py`
{% highlight python %}
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
        'Session': [None, ["Pointer", dict(target="_MM_SESSION_SPACE")]],
        'Token': [None, ["_EX_FAST_REF", dict(target="_TOKEN")]],
        }],
{% endhighlight %}

Here we see how much space the structure and each parameter occupies in memory.
There are concepts such as padding in a scanner, but since this is not the purpose of this article, I will touch on scanning in a superficial way.

{% highlight python %}
class BaseScanner(with_metaclass(registry.MetaclassRegistry, object)):
    """Base class for all scanners."""

    progress_message = "Scanning 0x%(offset)08X with %(name)s"

    checks = ()

    def __init__(self, profile=None, address_space=None, window_size=8,
                 session=None, checks=None):
        """The base scanner.

        Args:
           profile: The profile to use for this scan.
           address_space: The address space we use for scanning.
           window_size: The size of the overlap window between each buffer read.
        """
        self.session = session or address_space.session
        self.address_space = address_space or self.session.default_address_space
        self.window_size = window_size
        self.constraints = None
        if profile is None and self.session.HasParameter("profile"):
            profile = self.session.profile

        self.profile = profile
        self.max_length = None
        self.base_offset = None
        self.scan_buffer_offset = None
        self.buffer_as = addrspace.BufferAddressSpace(session=self.session)
        if checks is not None:
            self.checks = checks
# .....................
{% endhighlight %}
For more code and to learn the scanning process completely : 
```
rekall-core\rekall\plugins\common\scanners.py
rekall-core\rekall\scan.py
```

# Manual Mem File Analysis With Rekall
Now we come to the main topic of this article. In this section, we will try to find process injection methods in the image.
First, let me talk about the classical way that we will use in every method. In the classic way, after getting information about the process, we will dump the malicious dll inside and analyze it in the classic way.
First sample, the classic Process Injection technique. The technique using CreateRemoteThread and LoadLibrary.
A dll named `ShellcodeDLL.dll` has been injected into the notepad.exe process. Now let's analyze this process with Rekall. Start rekall with 

`$utku > .\rekal.exe -f memdump.mem`

and use the pslist() function to see the processes in the image.
![Screenshot_1](https://user-images.githubusercontent.com/54905232/190439769-fa98a563-491f-4bcd-ac14-da1f6cac82cf.png)

It is quite difficult to see the name notepad.exe here. Let's try again using the `pslist(proc_regex="notepad.exe")` command.

```
[1] memdump.mem 18:08:13> pslist(proc_regex="notepad.exe")
0x800c3babf080 Notepad.exe -- pid: 30248
Out<18:08:13> Plugin: pslist (WinPsList)
```
OK, now let's look at the dll files inside.

```
[1] memdump.mem 21:25:27> dlllist(proc_regex="notepad.exe")
Notepad.exe pid: 30248
  0x7ffd2d440000  0x209000 LoadReasonStaticDependency  C:\Windows\SYSTEM32\ntdll.dll
  0x7ffd2c0d0000   0xbd000 LoadReasonDynamicLoad       C:\Windows\System32\KERNEL32.DLL
  0x7ffd2a920000  0x37c000 LoadReasonStaticDependency  C:\Windows\System32\KERNELBASE.dll
  0x7ffd2c680000   0x5d000 LoadReasonStaticDependency  C:\Windows\System32\SHLWAPI.dll
  0x7ffd2c460000   0xa3000 LoadReasonStaticDependency  C:\Windows\System32\msvcrt.dll
  0x7ffd2ced0000  0x1ad000 LoadReasonStaticDependency  C:\Windows\System32\USER32.dll
  ......
  0x7ffd0b2d0000   0x25000 LoadReasonDynamicLoad       C:\ShellcodeDLL.dll
  0x7ffd0b2a0000   0x2b000 LoadReasonStaticDependency  C:\Windows\SYSTEM32\VCRUNTIME140D.dll
  0x7ffc4e000000  0x221000 LoadReasonStaticDependency  C:\Windows\SYSTEM32\ucrtbased.dll
Out<21:25:27> Plugin: dlllist (WinDllList)
[1] memdump.mem 21:26:02>
```
Our goal is clear :D. Now let's dump.

```
[1] memdump.mem 21:26:02> dlldump(proc_regex="notepad", dump_dir="C:/tmp/")
0x800c3babf080 module.30248.26b2bf080.7ff6fa660000.Notepad.exe
..........
0x800c3babf080 module.30248.26b2bf080.7ffd0b2d0000.ShellcodeDLL.dll
0x800c3babf080 module.30248.26b2bf080.7ffd0b2a0000.VCRUNTIME140D.dll
0x800c3babf080 module.30248.26b2bf080.7ffc4e000000.ucrtbased.dll
```

Now we have the dll files in the `C:/tmp/` directory. Let's analyze the dll file with IDA. When I decompile the entry point:

{% highlight c %}
__int64 __fastcall sub_7FFD0B2E1650(__int64 a1, int a2)
{
  int v3; // [rsp+118h] [rbp+F8h]

  v3 = a2;
  sub_7FFD0B2E12C1(&unk_7FFD0B2F1001); // GetCurrentThreadId();
  if ( v3 )
  {
    switch ( v3 )
    {
      case 1:
        MessageBoxA(0i64, "heyooo Process Attach", "from Shellcode", 0x11u);
        break;
      case 2:
        MessageBoxA(0i64, "heyooo Thread Attach", "from Shellcode", 0x11u);
        break;
      case 3:
        MessageBoxA(0i64, "heyooo Thread Detach", "from Shellcode", 0x11u);
        break;
    }
  }
  else
  {
    MessageBoxA(0i64, "heyooo Process Detach", "from Shellcode", 0x11u);
  }
  return 1i64;
}
{% endhighlight %}

I wrote this DLL File, so it is not harmful. It was written only for testing and for demonstration on rekall. I will use Docker as I need to edit in rekall for further operations. After installing Docker on your device, let's install rekall with the command below.


```
$utku > docker pull remnux/rekall
Using default tag: latest
latest: Pulling from remnux/rekall
Digest: sha256:301664d32ebee20c8653ea137e414f938e6b717e1eebcf62cb8e690433cee627
Status: Image is up to date for remnux/rekall:latest
docker.io/remnux/rekall:latest
$utku > docker run --name rekallcontainer -it -u 0 remnux/rekall
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@8766029683e9:~/files$ rekall
Webconsole disabled: cannot import name 'webconsole_plugin' from partially initialized module 'rekall.plugins.tools' (most likely due to a circular import) (/usr/local/lib/python3.8/dist-packages/rekall/plugins/tools/__init__.py)

----------------------------------------------------------------------------
The Rekall Digital Forensic/Incident Response framework 1.7.2.rc1 (Hurricane Ridge).

"We can remember it for you wholesale!"

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License.

See http://www.rekall-forensic.com/docs/Manual/tutorial.html to get started.
----------------------------------------------------------------------------
[1] Default session 20:02:05>
```

The point of running on Docker is that I can't fix dependencies with old Python version. Since I'm going to edit via google/rekall, let's download the repo with `git clone https://github.com/google/rekall.git` command and test it again.
The command we enter to run rekall from this repo:

```
root@8766029683e9:~/files$ rekall -f memdump.mem
(..........)
[1] Default session 20:33:57>
```

We need to dump the mem file on our device to docker. We can do it with this: `docker cp .\memdump.mem rekallcontainer:/`

> and `mv memdump.mem home/nonroot/files/` for move to the work directory.

## DLL Injection Detector Script

Since YARA is already a well-known method, we will try a different technique. The technique we will try will be probabilistic. But it will make the analyst's job a lot easier. Since we are using the `CreateRemoteThread -> LoadLibrary` method, which is the most classic method of DLL Injection, our script will print pids when it catches the address starting with _LoadLibraryW_ between threads. 
My goal is to develop an interactive plugin for rekall. I will then run it in rekall with the `run -i test.py` command. The documentation on the Rekall page is sufficient for this process. [document](http://www.rekall-forensic.com/documentation-1/rekall-documentation/tutorial)

[GitHub Gist](https://gist.github.com/polynomen/fbe662fb45d91c6133fb885c626c1f7f)
{% highlight python %}
"""
Classic DLL Injection technique detector rekall plugin
by Utku Corbaci ~ Malwation

Twitter: @rhotav
GitHub : @polynomen
"""

suspiciousPids = []

def detect(pid):
    threads = session.plugins.threads(pid)
    for threadx in threads:
            if("kernel32!LoadLibraryW" in str(threadx["win32_start_symb"])):
                    suspiciousPids.append((pid, threadx["Process"]))
                    break
try:
    pslist = session.plugins.pslist()
    for task in pslist.filter_processes():
        if(task.name == "lsass.exe"): # for Windows11 OS Version Errors
            continue
        detect(task.UniqueProcessId)
    if(len(suspiciousPids) > 0):
        print(" ")
        print("\nSuspicious PIDs:\n")
        for pid, addressThread in suspiciousPids:
            print("PID: %d Process: %s" % (pid, addressThread))
    else:
        print("No suspicious PIDs found.")
except Exception as e:
    print(e)
{% endhighlight %}

Output:

```
[1] memdump.mem 21:22:00> run -i test.py
 (................)
 Trying to fetch http://msdl.microsoft.com/download/symbols/ntdll.pdb/F9AA2E4EE66A1A6368DC07768AAA16EB1/ntdll.pdb
 Merging export table: JetOpenTableW
Suspicious PIDs:

PID: 10404 Process: firefox.exe
PID: 22732 Process: ServiceHub.Set
PID: 30248 Process: Notepad.exe
```

The plugins in Rekall are all in the sessions.plugins.* path. We must interpret the output correctly. For example, I analyzed the classes defined to understand dict structures. For example output of the `threads` command:

`rekall-core\rekall\plugins\windows\taskmods.py`

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

> After using the interactive plugins, we interpreted the output and read the codebase for this

## Process Hollowing Detector Script
As there are many articles on the internet about how these techniques work, I will not explain exactly how they work. I will only explain what we will use for analysis.
If you don't know exactly how the techniques we will use work, check [here](https://docs.google.com/viewerng/viewer?url=https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf).

In short, the functions used:
1. CreateProcess
2. NtUnmapViewOfSection
3. VirtualAllocEx
4. WriteProcessMemory
5. SetThreadContext

Using [this](https://github.com/m0n0ph1/Process-Hollowing) project I will run a svchost.exe targeted process and take an image.
Let's first look at how it looks on rekall.
```
[1] memdump.mem 19:49:51> pslist(proc_regex="svchost.exe")
  _EPROCESS            name          pid   ppid 
-------------- -------------------- ----- --------
0xe681fcae90c0 svchost.exe            836   1100
0xe6820b75d080 svchost.exe          10468   1100
................................................
0xe68216b020c0 svchost.exe          10792  25480
0xe6820b4a5080 svchost.exe          10996   1100
0xe6820b5cd0c0 svchost.exe          12384   1100
0xe68215b740c0 svchost.exe          12640   1100
Out<19:49:51> Plugin: pslist (WinPsList)
[1] memdump.mem 19:49:51>
```

We have a lot of svchost.exe processes running in our image file, but there is one thing to be aware of here. Normally all of them have services.exe as parent process (ppid number) but one of them is strange. Instead of checking PID and PPID, I will just check imagebase in ldrmodules and check vad.

1. Check imagebase in ldrmodules
```
[1] memdump.mem 20:26:26> ldrmodules(10792)
       base      in_load in_init in_mem mapped
  -------------- ------- ------- ------ ------
--------------------------------
0xe68216b020c0 svchost.exe 10792
--------------------------------
0x77e40000 False   False   False  C:\Windows\SysWOW64\ntdll.dll
0x75d70000 False   False   False  C:\Windows\SysWOW64\ucrtbase.dll
0x6b4e0000 False   False   False  C:\Windows\SysWOW64\TextShaping.dll
0x6b3f0000 False   False   False  C:\Windows\SysWOW64\TextInputFramework.dll
0x74d20000 False   False   False  C:\Windows\SysWOW64\uxtheme.dll
0x742f0000 False   False   False  C:\Windows\SysWOW64\kernel.appcore.dll
0x75bc0000 False   False   False  C:\Windows\SysWOW64\msctf.dll
0x77330000 False   False   False  C:\Windows\SysWOW64\KernelBase.dll
0x76fa0000 False   False   False  C:\Windows\SysWOW64\kernel32.dll
0x76130000 False   False   False  C:\Windows\SysWOW64\combase.dll
0x76050000 False   False   False  C:\Windows\SysWOW64\msvcrt.dll
0x769d0000 False   False   False  C:\Windows\SysWOW64\imm32.dll
0x771d0000 False   False   False  C:\Windows\SysWOW64\sechost.dll
0x77090000 False   False   False  C:\Windows\SysWOW64\oleaut32.dll
0x77250000 False   False   False  C:\Windows\SysWOW64\msvcp_win.dll
0x77d10000 False   False   False  C:\Windows\SysWOW64\gdi32.dll
0x779a0000 False   False   False  C:\Windows\SysWOW64\user32.dll
0x777f0000 False   False   False  C:\Windows\SysWOW64\win32u.dll
0x77bc0000 False   False   False  C:\Windows\SysWOW64\rpcrt4.dll
0x77b50000 False   False   False  C:\Windows\SysWOW64\bcryptprimitives.dll
0x77d40000 False   False   False  C:\Windows\SysWOW64\gdi32full.dll
0x77e30000 True    True    True   C:\Windows\System32\wow64cpu.dll
0x7fff8a0e0000 True    True    True   C:\Windows\System32\wow64.dll
0x7fff8bd60000 True    True    True   C:\Windows\System32\wow64base.dll
0x7fff8a810000 True    True    True   C:\Windows\System32\wow64win.dll
0x7fff8a940000 True    True    True   C:\Windows\System32\wow64con.dll
0x7fff8bf60000 True    True    True   C:\Windows\System32\ntdll.dll
Out<20:26:26> Plugin: ldrmodules (LdrModules)
```
In this output we should actually see the path to svchost.exe but it is not there.

2. Check vad. Is there a section with EXECUTE_READWRITE permission?
```
[1] memdump.mem 20:27:10> vad(10792)
--------------------------------
0xe68216b020c0 svchost.exe 10792
--------------------------------
0xe6821d68cb40   4       0xb00000       0xb17fff     24 Private Exe    EXECUTE_READWRITE
0xe682139c5ce0   3       0xd00000      0x2cfffff      2 Mapped         NOACCESS
0xe68213d56e00   4      0x2d00000      0x2d00fff      0 Mapped         READONLY
0xe68213d562c0   2      0x2d10000      0x2d10fff      0 Mapped         READONLY
0xe68213d573a0   5      0x2d20000      0x2d20fff      0 Mapped         READONLY
```
Script:
{% highlight python %}
"""
Process Hollowing technique detector rekall plugin
by Utku Corbaci ~ Malwation

Twitter: @rhotav
GitHub : @polynomen

`run -i prochollow.py`
"""
suspiciousTasks = []

def protectTest(vadList):
    for vad in vadList:
        if(vad["protect"] == "EXECUTE_READWRITE"):
            return True
    return False

def isSuspicious(task):
    x = True
    vadList = session.plugins.vad().collect_vadroot(task.RealVadRoot, task)

    if(len(vadList) <= 3):
        return False

    for vad in vadList:
        filename = str(vad["filename"]).strip()
        if(filename == None):
            continue
        if(str(task.name) in filename):
            x = False
            break
    if(x):
        if(protectTest(vadList)):
            x = True
        else:
            x = False

    return x

def collectSuspiciousTasks():
    pslist = session.plugins.pslist()
    for task in pslist.filter_processes():
        if(task.name == "lsass.exe"): # for Windows11 OS Version Errors
            continue
        if(isSuspicious(task)):
            suspiciousTasks.append(task)

collectSuspiciousTasks()
if(len(suspiciousTasks) > 0):
    print(" ")
    print("Collected Suspicious PIDs:")
    for task in suspiciousTasks:
        print("PID: %d Process: %s" % (task.UniqueProcessId, task.name))
else:
    print("No suspicious PIDs found.")
{% endhighlight %}

Output:

```
[1] memdump.mem 20:27:10> run -i prochollow.py

Collected Suspicious PIDs:
PID: 3180 Process: OfficeClickToR
PID: 10792 Process: svchost.exe
```

