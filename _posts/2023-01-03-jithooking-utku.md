---
layout: post
title: .NET Just-In-Time (JIT) Compiler Hooking
date: 2023-01-03 16:43:47 +0300
description: Analysis of clrjit.dll and Hooking Its Function
author: Utku Çorbacı - @rhotav
comments: true
tags: [Coding, C#, .NET, Windows, JIT, EN]
---

This blog post is translated and developed from [rhotav.com](rhotav.com)'s blog post.

In fact, this process is no different from a normal API hooking. The main purpose of writing this article is Remote Process's clrjit hooking.

As you know, .NET applications written in C# contain MSIL codes. For the application to work properly, MSIL codes must be translated into machine code at runtime. Our goal is to be able to get MSIL codes during the code translation phase to avoid Anti-Tamper protections.

# Table Of Content
<pre>
1. Which function is the target?
    1.1 Examine clrjit.dll
2. JIT Hooking
    2.1 Local JIT Hooking
    2.2 Remote Process's JIT Hooking
</pre>

# Which function is the target?

In fact, different .NET applications can have two targets (mscorjit and clrjit). This is because in versions prior to .NET 4.0 the JIT is contained in mscorjit but We will analyze a application that running on the .NET 4.0+ so our target is clrjit.dll
We know that the target function is contained in clrjit.dll. Nevertheless, when we examine it with CFF, we see two functions.

## Examine clrjit.dll

![Screenshot_1](https://user-images.githubusercontent.com/54905232/104369067-f8bda700-552d-11eb-864e-15af6e52fcc7.png)

To choose between the two functions, let's go to the [dotnet/runtime](https://github.com/dotnet/runtime/blob/eb03112e4e715dc0c33225670c60c6f97e382877/src/coreclr/inc/corjit.h#L93) repository and analyze it.

```c
extern "C" void __stdcall jitStartup(ICorJitHost* host);

class ICorJitCompiler;
class ICorJitInfo;

extern "C" ICorJitCompiler* __stdcall getJit();

// #EEToJitInterface
// ICorJitCompiler is the interface that the EE uses to get IL bytecode converted to native code. Note that
// to accomplish this the JIT has to call back to the EE to get symbolic information.  The code:ICorJitInfo
// type passed as 'comp' to compileMethod is the mechanism to get this information.  This is often the more
// interesting interface.
//
//
class ICorJitCompiler
{
public:
    // compileMethod is the main routine to ask the JIT Compiler to create native code for a method. The
    // method to be compiled is passed in the 'info' parameter, and the code:ICorJitInfo is used to allow the
    // JIT to resolve tokens, and make any other callbacks needed to create the code. nativeEntry, and
    // nativeSizeOfCode are just for convenience because the JIT asks the EE for the memory to emit code into
    // (see code:ICorJitInfo.allocMem), so really the EE already knows where the method starts and how big
    // it is (in fact, it could be in more than one chunk).
    //
    // * In the 32 bit jit this is implemented by code:CILJit.compileMethod
    // * For the 64 bit jit this is implemented by code:PreJit.compileMethod
    //
    // Note: Obfuscators that are hacking the JIT depend on this method having __stdcall calling convention
    virtual CorJitResult __stdcall compileMethod (
            ICorJitInfo                 *comp,               /* IN */
            struct CORINFO_METHOD_INFO  *info,               /* IN */
            unsigned /* code:CorJitFlag */   flags,          /* IN */
            BYTE                        **nativeEntry,       /* OUT */
            ULONG                       *nativeSizeOfCode    /* OUT */
            ) = 0;

```

As you can understand from the comment lines, the function we need to hook is compileMethod(). The target function is in a class so we need the output of the getJit function to get the address of this class.

Function that performs the machine code conversion according to the data received in the `CORINFO_METHOD_INFO` structure. Let's take a look at this structure:

{% highlight cpp %}
struct CORINFO_METHOD_INFO
{
    CORINFO_METHOD_HANDLE       ftn;
    CORINFO_MODULE_HANDLE       scope;
    BYTE *      ILCode;
    unsigned    ILCodeSize;
    unsigned    maxStack;
    unsigned    EHcount;
    CorInfoOptions      options;
    CorInfoRegionKind   regionKind;
    CORINFO_SIG_INFO    args;
    CORINFO_SIG_INFO    locals;
};

struct CORINFO_SIG_INFO
{
    CorInfoCallConv callConv;
    CORINFO_CLASS_HANDLE    retTypeClass;   // if the return type is a value class, this is its handle (enums are normalized)
    CORINFO_CLASS_HANDLE    retTypeSigClass;// returns the value class as it is in the sig (enums are not converted to primitives)
    CorInfoType     retType : 8;
    unsignedflags   : 8;    // used by IL stubs code
    unsignednumArgs : 16;
    struct CORINFO_SIG_INST sigInst;  // information about how type variables are being instantiated in generic code
    CORINFO_ARG_LIST_HANDLE args;
    PCCOR_SIGNATURE pSig;
    unsignedcbSig;
    CORINFO_MODULE_HANDLE   scope;  // passed to getArgClass
    mdToken token;

    CorInfoCallConv     getCallConv()       { return CorInfoCallConv((callConv & CORINFO_CALLCONV_MASK)); }
    boolhasThis()   { return ((callConv & CORINFO_CALLCONV_HASTHIS) != 0); }
    boolhasExplicitThis()   { return ((callConv & CORINFO_CALLCONV_EXPLICITTHIS) != 0); }
    unsigned    totalILArgs()       { return (numArgs + hasThis()); }
    boolisVarArg()  { return ((getCallConv() == CORINFO_CALLCONV_VARARG) || (getCallConv() == CORINFO_CALLCONV_NATIVEVARARG)); }
    boolhasTypeArg(){ return ((callConv & CORINFO_CALLCONV_PARAMTYPE) != 0); }
};
{% endhighlight %}

Did you notice some parameters in the CORINFO_METHOD_INFO structure? The storage address and length of IL codes!

# JIT Hooking
## Local JIT Hooking

Procedures for Local JIT Hooking:
1. The value given by `getJit()` is a VTable. Therefore, the first pointer in this table will give us the target function
2. We will get the target function address with the Marshal.ReadIntPtr function.
3. We will prepare a fake compileMethod After writing the necessary structures in C# 

This is the procedure. There's only one mistake. Since the JIT we will intervene will include the hooking C# codes we wrote, we will get StackoverFlowException. Before starting the hooking process, we need to PreCompile the code so that it is not sent back to the JIT.

{% highlight csharp %}

//..... Structures...

unsafe static void Main(string[] args)
{
    uint old;
    Context.delCompileMethod hookedCompileMethod = HookedCompileMethod;
    var vTable = getJit(); //get ICorJitCompiler's pointer
    var compileMethodPtr = Marshal.ReadIntPtr(vTable); //get compileMethod function's address
    OrigCompileMethod = (Context.delCompileMethod)Marshal.GetDelegateForFunctionPointer(Marshal.ReadIntPtr(compileMethodPtr), typeof(Context.delCompileMethod));

    if (!VirtualProtect(compileMethodPtr, (uint)IntPtr.Size, 0x40, out old))
    return;

    RuntimeHelpers.PrepareDelegate(hookedCompileMethod); // PreCompile events
    RuntimeHelpers.PrepareDelegate(OrigCompileMethod);

    Marshal.WriteIntPtr(compileMethodPtr, Marshal.GetFunctionPointerForDelegate(hookedCompileMethod)); //We took the address of our fake function and printed it in place of the compileMethod pointer.
    VirtualProtect(compileMethodPtr, (uint)IntPtr.Size, old, out old);

    Console.WriteLine(testFunc()); 

    if (!VirtualProtect(compileMethodPtr, (uint)IntPtr.Size, 0x40, out old)) 
        return; 

    Marshal.WriteIntPtr(compileMethodPtr, Marshal.GetFunctionPointerForDelegate(OrigCompileMethod)); //To run the function normally, we revert it back.
    Console.WriteLine("Not Working");
    Console.ReadKey();
}

public static string testFunc()
{
    return "Working";
}

private static unsafe int HookedCompileMethod(IntPtr thisPtr, [In] IntPtr corJitInfo,
 [In] Context.CorMethodInfo* methodInfo, Context.CorJitFlag flags,
[Out] IntPtr nativeEntry, [Out] IntPtr nativeSizeOfCode)
{
    int token;
    Console.WriteLine("Compilation:\r\n");
    Console.WriteLine("Token: " + (token = (0x06000000 + *(ushort*)methodInfo->methodHandle)).ToString("x8"));//Token calculation.
    Console.WriteLine("Name: " + typeof(Program).Module.ResolveMethod(token).Name);
    Console.WriteLine("Body size: " + methodInfo->ilCodeSize);

    var bodyBuffer = new byte[methodInfo->ilCodeSize];
    Marshal.Copy(methodInfo->ilCode, bodyBuffer, 0, bodyBuffer.Length);

    Console.WriteLine("Body: " + BitConverter.ToString(bodyBuffer));

    return OrigCompileMethod(thisPtr, corJitInfo, methodInfo, flags, nativeEntry, nativeSizeOfCode);
}

{% endhighlight %}

![1](https://user-images.githubusercontent.com/54905232/104839465-66712680-58d2-11eb-9a95-65a4a939cd6b.png)

## Remote Process's JIT Hooking

Although DLL Injection comes to mind first for this process, we will try a different method. `AppDomain`. Each .NET Application runs in an AppDomain (see [MSDN](https://learn.microsoft.com/en-us/previous-versions/visualstudio/visual-studio-2008/cxk374d9(v=vs.90)?redirectedfrom=MSDN) for more explanation). Therefore, when we invoke the entry point of the target application, they will run in the same AppDomain, so there is no need for DLL Injection. 

So, the only difference from Local JIT Hooking is that the entry point of the target application is invoked.

```csharp
// .....
if (Context._jitHook.Hook(Context.HookedCompileMethod))
{
    Context.assembly.EntryPoint.Invoke(null, parameters);
}
// ....
```

You can access my related JIT Killer (JITK) project [here](https://github.com/rhotav/JITK).

# References

[https://github.com/dotnet/coreclr](https://github.com/dotnet/coreclr)

[https://xoofx.com/blog](https://xoofx.com/blog/2018/04/12/writing-managed-jit-in-csharp-with-coreclr/#)

[https://www.mono-project.com/news/2018/09/11/csharp-jit/](https://www.mono-project.com/news/2018/09/11/csharp-jit/)

[SJITHook](https://github.com/maddnias/SJITHook)

[rhotav.com](https://rhotav.com)
