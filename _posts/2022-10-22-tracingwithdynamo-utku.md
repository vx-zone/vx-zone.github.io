---
layout: post
title: Tracing and Manipulating with DynamoRIO
date: 2022-10-22 10:48:23 +0300
description: Let's do something with the mighty DynamoRIO.
author: Utku Çorbacı
comments: true
tags: [Tracing, Manipulating, EN]
---

In this blog post, i'll explain how to trace and manipulate a program with DynamoRIO. I'll use a simple program to explain the concepts (Source code is below this post). 

# Table Of Contents
<pre>
1. DynamoRIO Basics
    1.1 What Is DynamoRIO
    1.2 How It Works
        1.2.1 Code Cache and Basic Block
2. Call Tracing With DynamoRIO
    2.1 Libraries
    2.2 Interface Functions
3. Manipulating Anti-Detection Techniques
    3.1 Create Test Application
    3.2 Manipulate with DrWrap
</pre>

# DynamoRIO Basics
## What Is DynamoRIO
DynamoRIO is a dynamic binary _instrumentation_ framework. It is a tool that can be used to very purposes but we'll use it for tracing and manipulating and It's open source, can be found on [GitHub](https://github.com/DynamoRIO/dynamorio)

from DynamoRIO's website:
> DynamoRIO is a runtime code manipulation system that supports code transformations on any part of a program, while it executes. DynamoRIO exports an interface for building dynamic tools for a wide variety of uses: program analysis and understanding, profiling, instrumentation, optimization, translation, etc. Unlike many dynamic tool systems, DynamoRIO is not limited to insertion of callouts/trampolines and allows arbitrary modifications to application instructions via a powerful IA-32/AMD64/ARM/AArch64 instruction manipulation library. DynamoRIO provides efficient, transparent, and comprehensive manipulation of unmodified applications running on stock operating systems (Windows, Linux, or Android, with experimental Mac support) and commodity IA-32, AMD64, ARM, and AArch64 hardware.

DynamoRIO presented by Derek L. Bruening with a [whitepaper](https://www.burningcutlery.com/derek/docs/phd.pdf) at 2004 September. It's a very old project but still maintained and developed. This whitepaper title is "Efficient, Transparent, and Comprehensive Runtime Code Manipulation". At the beginning of the article they explain their goals and then they explain how DynamoRIO simply works. We need to use this library when writing any client. It contains the main functions that DynamoRIO will run on the client.

## How It Works

> DynamoRIO interposes itself between an application and the underlying operating system and hardware. It executes a copy of the application’s code out of a code cache to avoid emulation overhead.

![Screenshot_1](https://user-images.githubusercontent.com/54905232/197329358-8dc8614f-c1a7-4001-9289-12ce5a7dcb6f.png)

### Code Cache

We will do all of our work in the Code Cache section. Therefore, that is the point I want to specifically mention. With the "Code Cache" technology specially designed in DynamoRIO, we can monitor and modify each instruction before it runs. DynamoRIO creates a special section called Code Cache. DynamoRIO has got full authority over this section.

![Screenshot_2](https://user-images.githubusercontent.com/54905232/197329816-18fcd56f-a55f-4058-b73f-0c3e9ed0727a.png)

> The code cache enables native execution to replace emulation, bringing performance down from a several hundred times slowdown for pure emulation to an order of magnitude.

Instrumented application's instructions is keep in Code Cache as "basic block". \
In fact, every structure in DynamoRIO is very detailed. But I want to go directly to the application part without explaining the details too much.


# Call Tracing With DynamoRIO

We have got a very basic example application for tracing. Source code:

{% highlight c %}
int main()
{
    if (IsDebuggerPresent()) {
        std::cout << "uppss debugger detected\n";
        exit(0);
    }
    std::cout << "Hello World!\n";
    char merhaba[6] = "hello";
    LPCWSTR filepath = L"hello.txt";
    WriteToFile(merhaba, filepath);
}
{% endhighlight %}

## Libraries
Let's make a tracer with DynamoRIO's basic functions. Firstly, we need DynamoRIO's libraries so i'll include these on my project

{% highlight c %}
#include "dr_api.h"
#include "drmgr.h"
#include "utils.h"
{% endhighlight %}

utils.h need for logging operations never mind it. `dr_api.h` we need to use this library when writing any client. It contains the main functions that DynamoRIO will run on the client. `drmgr.h` multi instrumentation library that contains functions to manage basic block operations and instruction operations. 

## Interface Functions
Now we will define the 4 functions we need to define in the basic structure of the client. Thread init and exit, client exit (event exit) and the function that manages basic blocks.

{% highlight c %}
static void event_exit(void);
static void event_thread_init(void *drcontext);
static void event_thread_exit(void *drcontext);
static dr_emit_flags_t event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data);
{% endhighlight %}

Ok, now we can write the dr_client_main function which is the EntryPoint of the application. In this function we will save the event functions we defined before.

{% highlight c %}
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    call_from = true;
    dr_set_client_name("Maestro - API Tracer by rhotav",
                       "https://vx.zone");
    drmgr_init();
    dr_fprintf(STDERR, "Scope: %s\n", dr_get_application_name());
    my_id = id;
    dr_log(NULL, DR_LOG_ALL, 1, "Client 'maestro' initializing\n");

#ifdef SHOW_RESULTS
    if (dr_is_notify_on()) {
        dr_fprintf(STDERR, "Client maestro is running\n");
    }
#endif

    dr_register_exit_event(event_exit);
    drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);
    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);
    tls_idx = drmgr_register_tls_field();
    DR_ASSERT(tls_idx > -1);
}

static void event_exit(void)
{
    drmgr_unregister_tls_field(tls_idx);
    drmgr_exit();
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data)
{
    if (instr_is_call_indirect(instr)) {
        dr_insert_mbr_instrumentation(drcontext, bb, instr, (app_pc)at_call_ind,
                                      SPILL_SLOT_1);
    } 
    return DR_EMIT_DEFAULT;
}
{% endhighlight %}

`event_app_instruction`: This function is intercept all instruction at runtime. Our goal is to show the user ONLY where the CALL instructions in the target application make calls (except system dlls). For this, we need to write a function that will execute every time a CALL instruction is caught. 

{% highlight c %}
// PFX = "%p"

static void print_address(file_t f, app_pc addr, const char *prefix)
{
    drsym_error_t symres;
    drsym_info_t sym;
    char name[MAX_SYM_RESULT];
    char file[MAXIMUM_PATH];
    module_data_t *data;
    data = dr_lookup_module(addr);
    if (data == NULL) {
        dr_fprintf(f, "%s " PFX " ? ??:0\n", prefix, addr);
        return;
    }
    sym.struct_size = sizeof(sym);
    sym.name = name;
    sym.name_size = MAX_SYM_RESULT;
    sym.file = file;
    sym.file_size = MAXIMUM_PATH;
    symres = drsym_lookup_address(data->full_path, addr - data->start, &sym,
                                  DRSYM_DEFAULT_FLAGS);
    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
        const char *modname = dr_module_preferred_name(data); // get active module name
        if (modname == NULL)
            modname = "<noname>";
        if (strstr(prefix, "CALL")) {
            if (!strstr(modname, dr_get_application_name())) { //for only give main module call instructions
                call_from = false;
                dr_free_module_data(data);
                return;
            }
        }
        if (strstr(prefix, "to")) {
            if (!call_from) {
                dr_free_module_data(data);
                return;
            }
        }
        call_from = true;
        dr_fprintf(f, "%s " PFX " %s!%s", prefix, addr, modname, sym.name);
        if (symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
            dr_fprintf(f, " ??:0\n");
        } else {
            //dr_fprintf(f, " %s:%" UINT64_FORMAT_CODE "+" PIFX "\n", sym.file, sym.line, sym.line_offs);
            dr_fprintf(f, "\n");
        }
    } else
        dr_fprintf(f, "%s " PFX " ? ??:0\n", prefix, addr);
    dr_free_module_data(data);
}

static void at_call_ind(app_pc instr_addr, app_pc target_addr)
{
    file_t f = (file_t)(ptr_uint_t)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx); //Logging
    print_address(f, instr_addr, "CALL INDIRECT @ ");
    print_address(f, target_addr, "\t to ");
}
{% endhighlight %}

After writing the function that will be executed during each CALL instruction (at_call_ind), I write the print_address function for a different logging operation. This function presents the symbols of the requesting and received address to the user. 

Now let's see how it comes out.

```
%utku> .\drrun.exe -c maestro.dll -- "API Test Dynamo.exe"
Scope: API Test Dynamo.exe
Client maestro is running
Data file utku\Desktop\maestro.API Test Dynamo.exe.09628.0000.log created
Hello World!
Wrote 7 bytes to "utku\Desktop\merhaba.txt" successfully.
```

Log file:

```
CALL INDIRECT @  0x00007ff642a810e3 API Test Dynamo.exe!main
	 to  0x00007ffa20f47c40 KERNEL32.dll!IsDebuggerPresent ??:0
CALL INDIRECT @  0x00007ff642a812ab API Test Dynamo.exe!std::operator<<<>
	 to  0x00007ff9f20c6770 MSVCP140.dll!std::ios_base::_Init ??:0
CALL INDIRECT @  0x00007ff642a8134e API Test Dynamo.exe!std::operator<<<>
	 to  0x00007ff9f20c8fb0 MSVCP140.dll!std::ctype<>::toupper ??:0
CALL INDIRECT @  0x00007ff642a813bc API Test Dynamo.exe!std::operator<<<>
	 to  0x00007ff9f20c8d80 MSVCP140.dll!std::basic_ios<>::setstate ??:0
CALL INDIRECT @  0x00007ff642a813c3 API Test Dynamo.exe!std::operator<<<>
	 to  0x00007ff9f20d3ec0 MSVCP140.dll!std::uncaught_exception ??:0
CALL INDIRECT @  0x00007ff642a813d0 API Test Dynamo.exe!std::operator<<<>
	 to  0x00007ff9f20cb290 MSVCP140.dll!std::basic_ostream<>::_Osfx ??:0
CALL INDIRECT @  0x00007ff642a813eb API Test Dynamo.exe!std::operator<<<>
	 to  0x00007ff9f20c69e0 MSVCP140.dll!std::ios_base::_Tidy ??:0
CALL INDIRECT @  0x00007ff642a81184 API Test Dynamo.exe!main
	 to  0x00007ffa20f50180 KERNEL32.dll!CreateFileW ??:0
CALL INDIRECT @  0x00007ff642a811c3 API Test Dynamo.exe!main
	 to  0x00007ffa20f50610 KERNEL32.dll!WriteFile ??:0
CALL INDIRECT @  0x00007ff642a81038 API Test Dynamo.exe!wprintf
	 to  0x00007ffa1f6a7d40 ucrtbase.dll!_acrt_iob_func ??:0
CALL INDIRECT @  0x00007ff642a81057 API Test Dynamo.exe!wprintf
	 to  0x00007ffa1f682330 ucrtbase.dll!_stdio_common_vfwprintf ??:0
CALL INDIRECT @  0x00007ff642a81200 API Test Dynamo.exe!main
	 to  0x00007ffa20f4ff00 KERNEL32.dll!CloseHandle ??:0
CALL INDIRECT @  0x00007ff642a81d6a API Test Dynamo.exe!__scrt_is_managed_app
	 to  0x00007ffa20f46580 KERNEL32.dll!GetModuleHandleW ??:0
```

# Manipulating Anti-Detection Techniques
In this section we will manipulate the anti-debug (IsDebuggerPresent) and anti-vmware technique. Of course, I start by writing a test application first.


## Create Test Application

{% highlight cpp %}
#include <iostream>
#include "Windows.h"

void WriteToFile(char* data, LPCWSTR filename)
{
    HANDLE hFile;
    DWORD dwBytesToWrite = strlen(data);
    DWORD dwBytesWritten;
    BOOL bErrorFlag = FALSE;

    hFile = CreateFileW(filename,  // name of the write
        FILE_APPEND_DATA,          // open for appending
        FILE_SHARE_READ,           // share for reading only
        NULL,                      // default security
        OPEN_ALWAYS,               // open existing file or create new file 
        FILE_ATTRIBUTE_NORMAL,     // normal file
        NULL);                     // no attr. template

    if (hFile == INVALID_HANDLE_VALUE)
    {
        wprintf(L"Terminal failure: Unable to create/open file \"%s\" for writing.\n", filename);
        return;
    }

    while (dwBytesToWrite > 0)
    {
        bErrorFlag = WriteFile(
            hFile,              // open file handle
            data,               // start of data to write
            dwBytesToWrite,     // number of bytes to write
            &dwBytesWritten,    // number of bytes that were written
            NULL);              // no overlapped structure

        if (!bErrorFlag)
        {
            printf("Terminal failure: Unable to write to file.\n");
            break;
        }

        wprintf(L"Wrote %u bytes to \"%s\" successfully.\n", dwBytesWritten, filename);

        data += dwBytesWritten;
        dwBytesToWrite -= dwBytesWritten;
    }

    CloseHandle(hFile);
}

BOOL Is_RegKeyExists(HKEY hKey, LPCWSTR lpSubKey)
{
    HKEY hkResult = NULL;
    TCHAR lpData[1024] = { 0 };
    DWORD cbData = MAX_PATH;

    if (RegOpenKeyEx(hKey, lpSubKey, NULL, KEY_READ, &hkResult) == ERROR_SUCCESS)
    {
        RegCloseKey(hkResult);
        return TRUE;
    }

    return FALSE;
}

//al-khaser
VOID vmware_reg_key()
{
    LPCWSTR blacklisted = L"SOFTWARE\\VMware, Inc.\\VMware Tools";
    if (Is_RegKeyExists(HKEY_LOCAL_MACHINE, blacklisted))
    {
        printf("VM Detected\n");
        exit(0);
    }
    else
    {
        printf("Clear\n");
    }
}

int main()
{
    if (IsDebuggerPresent()) {
        std::cout << "uppss debugger detected\n";
        exit(0);
    }
    vmware_reg_key();
    std::cout << "Hello World!\n";
    char merhaba[6] = "hello";
    LPCWSTR filepath = L"hello.txt";
    WriteToFile(merhaba, filepath);
}
{% endhighlight %}

My test application is checking debugger with IsDebuggerPresent API and checking VMWare tool reg key.

## Manipulate with DrWrap
I mentioned that DynamoRIO has a lot of authority over the virtual memory it generates and gives us a lot of possibilities. DrWrap is one of those possibilities... [Function Wrapping and Replacing](https://dynamorio.org/group__drwrap.html)

A library that allows us to run before and after the target function and to analyze the instructions before the function runs. I will show the structures that we need to use specially in the application section.

Now, let's write main and register our functions. There are several functions and structures we will meet here. I will explain them after writing.

{% highlight cpp %}
DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("Manipulater for anti-detection techniques 'maestro2'", "https://vx.zone");
    dr_log(NULL, DR_LOG_ALL, 1, "Client 'maestro2' initializing\n");

#ifdef SHOW_RESULTS
    if (dr_is_notify_on()) {
        dr_fprintf(STDERR, "Client maestro2 is running\n");
    }
#endif
    drmgr_init();
    drwrap_init();
    dr_register_exit_event(event_exit);
    drmgr_register_module_load_event(module_load_event);
    max_lock = dr_mutex_create();
}
{% endhighlight %}

`drmgr_register_module_load_event`: This function is called when the module is loaded. In order to search for the functions we want to hook, we need to run an event every time a module is loaded. So we create a function.

Firstly, we need to examine wrap func and its args:
```
DR_EXPORT bool drwrap_wrap 	( 	app_pc  	func,
		void(*)(void *wrapcxt, OUT void **user_data)  	pre_func_cb,
		void(*)(void *wrapcxt, void *user_data)  	post_func_cb 
	) 	
```

Our bypass method here is to bypass the checks by treating the value returned by the function as harmless. 
We can specify individual functions to run before and after the target function. But according to our bypass method, there is no need to run anything else before.

{% highlight cpp %}
static void regOpenKey_post(void *wrapcxt, void *user_data)
{
    dr_fprintf(STDERR, "RegOpenKeyExW post wrap\n");
    drwrap_set_retval(wrapcxt, (void *)((LSTATUS)0));
    dr_fprintf(STDERR, "RegOpenKeyExW retval is 0\n");
}

static void debuggerWrap_post(void *wrapcxt, void *user_data)
{
    dr_fprintf(STDERR, "IsDebuggerPresent post wrap\n");
    drwrap_set_retval(wrapcxt, (void *)0);
    dr_fprintf(STDERR, "IsDebuggerPresent retval is 0\n");
}

static void module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
    app_pc isDebuggerPresentWrap = (app_pc)dr_get_proc_address(mod->handle, "IsDebuggerPresent");
    app_pc regKeyOpenWrap = (app_pc)dr_get_proc_address(mod->handle, "RegOpenKeyExW");

    if (isDebuggerPresentWrap != NULL) {
        drwrap_wrap(isDebuggerPresentWrap, NULL, debuggerWrap_post);
    }

    if (regKeyOpenWrap != NULL) {
        drwrap_wrap(regKeyOpenWrap, NULL, regOpenKey_post);
    }
}

static void event_exit(void)
{
    dr_mutex_destroy(max_lock);
    drwrap_exit();
    drmgr_exit();
}
{% endhighlight %}

Output:

```
%utku> .\drrun.exe -c wrap.dll -- "API Test Dynamo.exe"
Client maestro2 is running
RegOpenKeyExW post wrap
RegOpenKeyExW retval is 1
IsDebuggerPresent post wrap
IsDebuggerPresent retval is 0
RegOpenKeyExW post wrap
RegOpenKeyExW retval is 1
IsDebuggerPresent post wrap
IsDebuggerPresent retval is 0
debugger not detected
Clear
Hello World!
Wrote 5 bytes to "hello.txt" successfully.
```
