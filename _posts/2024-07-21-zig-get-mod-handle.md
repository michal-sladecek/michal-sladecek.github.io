---
layout: post
title: Compile time hashing in Zig
date: 2024-7-21 01:11 -0300
author: Michal
---


In this blog, I will go through a well-known technique of writing a custom win api resolver in Zig. I will use Zig's build system and comptime to dynamically generate hashes
of WinAPI on each compilation.


## Theory
The theory will be very short, as my main focus is to explain what I'm doing and how to do it in Zig. If you don't know why, I recommend reading any article about custom GetModuleHandle, there are plenty of them around the internet. So just to recap, a windows program can dynamically load code via:
1. Load-time dynamic linking - the DLL is specified in a special part of the PE file called Import Address Table(IAT), which tells the OS which DLLs to import during loading of the PE file.
2. Run-time dynamic linking - the DLL is loaded anytime during the program execution.

![functions in IAT]({{site.url}}/assets/zig02/iat_functions.png)
Load-time dynamic linking makes it very easy for AVs to see what the binary is importing - for example, a PE importing `CreateRemoteThread` is much more suspicious than PE loading a common function such as `MessageBoxA`. Therefore, we want to hide such functions and we need to use run-time loading. Run-time loading is performed using two functions:
1. `HMODULE GetModuleHandle(LPCSTR lpModuleName)` which returns a handle to the module specified in `lpModuleName`. This function will be the focus of today's blog.
2. `FARPROC GetProcAddress(HMODULE hModule, LPCSTR  lpProcName)`, which given a handle to a DLL and a function name returns pointer to the wanted function. This function will not be discuseed today, but I might push it to my github later.
These functions are used to mask what a binary does from static analysis. If we imported suspicious WinAPI functions directly, it would be bery obvious from the Import Address Table(IAT). Therefore, malware authors more often use dynamic resolution using these 2 functions. 

However, what if the AV hooks these two functions? They could see exactly which functions are loaded during runtime, and possibly block our execution once too many suspicious functions are loaded this way. To bypass this, we can implement these two functions from the scratch. I will focus on the `GetModuleHandle`, and leave the `GetProcAddress`.

The `GetProcAddress` does just three things, which our function also must do:
1. We need to find the list of loaded DLLs in the process memory.
2. Iterate over this list, until we find match with the one we are searching for.
3. Return the DLL's address in memory.

Let's start with a function that just prints all the loaded DLLs. The common technique used here is to traverse the Process Environment Block (PEB),
get pointer to the linked list of loaded modules and then iterate this list.

### PEB in Zig
Getting the PEB in Zig is very simple, as there is an stdlib implementation `std.os.windows.peb()`. The function returns a pointer to PEB structure, which we can check in the source code of Zig's std:
```zig
pub const PEB = extern struct {
    // Versions: All
    InheritedAddressSpace: BOOLEAN,

    // Versions: 3.51+
    ReadImageFileExecOptions: BOOLEAN,
    BeingDebugged: BOOLEAN,

    // Versions: 5.2+ (previously was padding)
    BitField: UCHAR,

    // Versions: all
    Mutant: HANDLE,
    ImageBaseAddress: HMODULE,
    Ldr: *PEB_LDR_DATA,
    // ... lots of other stuff we won't use
};
```
How nice from the Zig that its standard library contains even the undocumented PEB fields! We are only interested in the field `Ldr`, which is a pointer to `PEB_LDR_DATA`. This structure contains data about modules loaded in the process. The actual modules are in three linked list, and we will use `InLoadOrderModuleList`. The type of these lists is LIST_ENTRY according to the definition, but it's compatible with the structure LDR_DATA_TABLE_ENTRY. I show all structures here, copied from Zig's std: 

```zig
pub const PEB_LDR_DATA = extern struct {
    // Versions: 3.51 and higher
    /// The size in bytes of the structure
    Length: ULONG,

    /// TRUE if the structure is prepared.
    Initialized: BOOLEAN,

    SsHandle: PVOID,
    InLoadOrderModuleList: LIST_ENTRY,
    InMemoryOrderModuleList: LIST_ENTRY,
    InInitializationOrderModuleList: LIST_ENTRY,

    // Versions: 5.1 and higher

    /// No known use of this field is known in Windows 8 and higher.
    EntryInProgress: PVOID,

    // Versions: 6.0 from Windows Vista SP1, and higher
    ShutdownInProgress: BOOLEAN,

    /// Though ShutdownThreadId is declared as a HANDLE,
    /// it is indeed the thread ID as suggested by its name.
    /// It is picked up from the UniqueThread member of the CLIENT_ID in the
    /// TEB of the thread that asks to terminate the process.
    ShutdownThreadId: HANDLE,
};

pub const LIST_ENTRY = extern struct {
    Flink: *LIST_ENTRY,
    Blink: *LIST_ENTRY,
};

pub const LDR_DATA_TABLE_ENTRY = extern struct {
    Reserved1: [2]PVOID,
    InMemoryOrderLinks: LIST_ENTRY,
    Reserved2: [2]PVOID,
    DllBase: PVOID,
    EntryPoint: PVOID,
    SizeOfImage: ULONG,
    FullDllName: UNICODE_STRING,
    Reserved4: [8]BYTE,
    Reserved5: [3]PVOID,
    DUMMYUNIONNAME: extern union 
        CheckSum: ULONG,
        Reserved6: PVOID,
    },
    TimeDateStamp: ULONG,
};
```

The Zig's definition of the structure `LDR_DATA_TABLE_ENTRY` structure does not contain all the fields we need - we need to use the `BaseDllName` field, so we redefine the struct for our purpose and change the `Reserved4` field to `BaseDllName`:
```zig
pub const LDR_DATA_TABLE_ENTRY = extern struct {
    Reserved1: [2]std.os.windows.PVOID,
    InMemoryOrderLinks: std.os.windows.LIST_ENTRY,
    Reserved2: [2]std.os.windows.PVOID,
    DllBase: std.os.windows.PVOID,
    EntryPoint: std.os.windows.PVOID,
    SizeOfImage: std.os.windows.ULONG,
    FullDllName: std.os.windows.UNICODE_STRING,
    // Our addition - instead of Reserved4, we know this is really BaseDllName
    BaseDllName: std.os.windows.UNICODE_STRING,
    Reserved5: [3]std.os.windows.PVOID,
    DUMMYUNIONNAME: extern union {
        CheckSum: std.os.windows.ULONG,
        Reserved6: std.os.windows.PVOID,
    },
    TimeDateStamp: std.os.windows.ULONG,
};

```

With all structs ready, we can get to the actual implementation. I will first show the code and then explain some parts down.

```zig
fn traverseLoadedDLLs() !void {
    // We get the pointer to peb from Zig's stdlib
    const peb = std.os.windows.peb();
    // Get the first entry in the InLoadOrderModuleList linked list.
    var modules_linked_list = peb.Ldr.InLoadOrderModuleList.Flink;

    // We need to use an allocator in the loop - FixedBufferAllocator is basically an allocator that uses a buffer on stack.
    // Therefore, we first allocate buffer of 1000 bytes on stack.
    var buffer: [256]u8 = undefined;
    // We create an fixed buffer allocator
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    // Get the actual allocator from FixedBufferAllocator
    const alloc = fba.allocator();

    while (true) {
        // We need to cat the *LIST_ENTRY to a *LDR_DATA_TABLE_ENTRY
        const loaded_module: *LDR_DATA_TABLE_ENTRY = @ptrCast(modules_linked_list);
        // We get the name of the base dll name - it's encoded in unicode 16
        const mod_name_length = loaded_module.BaseDllName.Length / @sizeOf(u16);
        // Length 0 indicates the end of linked list
        if (mod_name_length == 0) break;

        // We get the module name in utf8 by converting utf16 to utf8.
        // The function uses our allocator to allocate the new buffer
        // Because Buffer can be NULL pointer, we need to dereference it with .? . Zig does not allow null pointers.
        const mod_name_utf8 = try std.unicode.utf16LeToUtf8Alloc(alloc, loaded_module.BaseDllName.Buffer.?[0..mod_name_length]);
        // We defer alloc.free so that the memory is freed when exiting the block
        defer alloc.free(mod_name_utf8);
        // Print module name and memory 
        std.debug.print("{s}: {}\n", .{ mod_name_utf8, loaded_module.DllBase });
        // Go to next loaded module
        modules_linked_list = modules_linked_list.Flink;
    }
}
```
While being quite similar to C, one thing that stands out is our converting of utf16 to utf8. We need to use an allocator, which is another Zig concept that is pretty interesting. While in other languages you mostly ignore memory allocation, in Zig you have a lot of control. Any function that returns a pointer should get an allocator from the caller.

We use the `FixedBufferAllocator`. We define a buffer on the stack and tell the function to allocate any memory it needs inside of that buffer. If we wanted, we could do heap allocations (but why would we when we know the DLL is not gonna be long?) or code an allocation strategy ourselves.

The code prints out all the modules loaded in current program:
![screenshot of output]({{site.url}}/assets/zig02/loaded_modules.png)


## Comptime hashing of module names
To actually resolve the module we want (let's say kernel32.dll), we need to be able to compare it with string "kernel32.dll". However, having strings of suspicious WinAPIs in your program 
might trigger some static detections, or at the very least, increase ML score of your program. Most malwares therefore use *hashes* of strings to resolve them.

We can code a simple hash function (djb2) in few lines:
```zig
// This is just implementation of djb2 from http://www.cse.yorku.ca/~oz/hash.html
fn hashString(s: []const u8) u64 {
    var hash: u64 = 5381;
    for (s) |c| {
        // We must use @addWithOverflow and @shlWithOverflow, as Zig would declare comptime error because of the overflow
        // The builtins return tuples with two values - the result in [0] and overflow bit in [1]
        hash = @addWithOverflow(@shlWithOverflow(hash, 5)[0], hash + std.ascii.toUpper(c))[0];
    }
    return hash;
}

```

Now comes the magic of Zig - using the `comptime` keyword, we can call this function at compile time:

```zig
// Function returns !?HINSTANCE. 
// ! - function can return an error. The utf16LeToUtf8Alloc function can fail, and we do not handle any errors inside the function.
// ? - function can return null. Zig does not allow pointers to null, instead it uses optionals which can either be null or pointers.
// This makes Zig safer, as you must be explicit when dereferencing null pointers
// Lastly, the function returns HINSTANCE. This is basically a pointer to the DLL in memory.
fn getModuleHandleHash(comptime moduleName: []const u8) !?HINSTANCE {
    // We compute the hash of the searched module at compile time using the comptime keyword

    const moduleHash = comptime hashString(moduleName);
    // From here, the function is the same as previous example
    const peb = std.os.windows.peb();

    var buffer: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const alloc = fba.allocator();

    var modules_linked_list = peb.Ldr.InLoadOrderModuleList.Flink;
    while (true) {
        const loaded_module: *LDR_DATA_TABLE_ENTRY = @ptrCast(modules_linked_list);
        const mod_name_length = loaded_module.BaseDllName.Length / @sizeOf(u16);
        if (mod_name_length == 0) break;

        const mod_name_utf8 = try std.unicode.utf16LeToUtf8Alloc(alloc, loaded_module.BaseDllName.Buffer.?[0..mod_name_length]);
        // Instead of prtinting, we try if the hash matches with the searched hash
        if (hashString(mod_name_utf8) == moduleHash) {
            return @ptrCast(loaded_module.DllBase);
        }
        alloc.free(mod_name_utf8);
        modules_linked_list = modules_linked_list.Flink;
    }
    return null;
}
```

To test this function, we can compare its output with the output of actual GetModuleHandle. Zig has built in testing functionality:
```zig
test "getModuleHandleHash kernel32.dll" {
    try std.testing.expectEqual(win32.everything.GetModuleHandleA("kernel32.dll").?, (try getModuleHandleHash("kernel32.dll")).?);
}
test "getModuleHandleHash ntdll.dll" {
    try std.testing.expectEqual(win32.everything.GetModuleHandleA("ntdll.dll").?, (try getModuleHandleHash("ntdll.dll")).?);
}
test "getModuleHandleHash nonexistent dll" {
    try std.testing.expectEqual(win32.everything.GetModuleHandleA("notexistent.dll"), try getModuleHandleHash("nosuchdll.dll"));
    try std.testing.expectEqual(null, try getModuleHandleHash("nosuchdll.dll"));
}
```


We can now run the tests to see if our function is correct. Also, we should check the binary to see if it contains some of the strings that we provided. Of course, it will contain notexistent.dll (as it was used in `GetModuleHandleA`), but it should not contain `nosuchdll.dll`.

![screenshot of output]({{site.url}}/assets/zig02/output_tests.png)

## Compile time randomness to change hashing algorithm
Golden rule of maldev is that anything static means signatures. Our hash function is pretty static, and if we would use it often AVs would signature our hashes. This happened to [Havoc's](https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/include/common/Defines.h) WinAPI hashes, and the signatures can be seen in [Elastic's repo](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_Havoc.yar).

![screenshot of Havoc's hardocoded winapi hashes]({{site.url}}/assets/zig02/havoc-hashes.png)

![screenshot of Elastic's Havoc's signatures]({{site.url}}/assets/zig02/havoc_yara.png)

We should make the signaturing as hard as possible, so we want to generate different hashes *on each payload compilation*. To my surprise, this is harder than expected. While Zig's comptime allows random number generators, the functions called at comptime must be pure. A function returning different number on each compilation is impure by definition, so we need a way out of `comptime` to generate a seed. 

What I do is get the seed as parameter from our build script, which in Zig is written in... Zig. That's right, you do not need Makefiles or bash scripts. We add new compile time switch seed, which if not provided will be the current timestap. I add following code into my `build.zig`:

```zig
const seed = b.option(i64, "seed", "rng seed") orelse std.time.timestamp();
const options = b.addOptions();
options.addOption(i64, "seed", seed);

```

Once we have the seed as compilation option, we can access it in source file with `config`. The changed part of code is just the initial hash:

```zig

fn getComptimeRandomNumber(comptime local_seed: comptime_int) comptime_int {
    // We use local_seed so that we can call this function in different places of source code, and get different results 
    // The config.seed is to make numbers different between builds and comes from build script. 
    comptime var rnd = RndGen.init(@as(u64, @bitCast(local_seed ^ config.seed)));
    return rnd.next();
}
fn hashString(s: []const u8) u64 {
    var hash: u64 = getComptimeRandomNumber(1);
    for (s) |c| {
        hash = @addWithOverflow(@shlWithOverflow(hash, 5)[0], hash + std.ascii.toUpper(c))[0];
    }
    return hash;
}
```

We can see that the tests still pass and that hashes are different on each run:

![screenshot of hashes]({{site.url}}/assets/zig02/hashes_1.png)
![screenshot of hashes]({{site.url}}/assets/zig02/hashes_2.png)


## Conclusion

Compile time hashing is very convenient to do in Zig. I also like that Zig's stdlib containst the windows undocumented APIs and I do not have to copy bindings for each struct, such as when coding in Visual Studio. Stay tuned for more Zig content in the future, there are still many features that I did not yet get to try such as inline assembly or more playing with Zig's build system.  The code was again pushed to my Github and you can play with it yourself.

 {% include social-media-share.html %}
