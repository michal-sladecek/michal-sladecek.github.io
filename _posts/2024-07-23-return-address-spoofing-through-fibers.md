---
layout: post
title: Return address spoofing through Fibers
date: 2024-7-23 01:11 -0300
author: Michal
---

I've been reading up about Fibers recently, and their offensive use is pretty interesting. I came up with very simple technique of spoofing return address  that I haven't seen mentioned during my reading of other blogs. Although not the best technique to spoof callstack, it's one that's very simple, does not need lots of code to work and does not invoke many syscalls.
If you just want the code(in Zig), it's in my [GH](https://github.com/michal-sladecek/zig_experiments/blob/master/src/fibers_ret_spoofing.zig).

## Theory

### Fibers
Accodring to [Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/procthread/fibers), fibers are units of execution that must be manually scheduled by the application. Very simplified, we can look at fibers as userland threads. These fibers have their own stacks, but all run in the same thread.

There's been lot of offensive research about fibers. Fibers have been used to:
- [run shellcode without CreateNewThread](https://www.ired.team/offensive-security/code-injection-process-injection/executing-shellcode-with-createfiber)
- [sleep outside of shellcode memory to hide its callstack](https://github.com/Kudaes/Fiber)

Another very interesting research is [Immoral Fiber](https://github.com/JanielDary/ImmoralFiber), though it mostly focuses on Fiber Local Storage which we don't use.
Fibers have also been used by real threat actors - APT41 uses fibers to schedule function calls in the [MoonWalk](https://www.zscaler.com/blogs/security-research/moonwalk-deep-dive-updated-arsenal-apt41-part-2) malware. 

### Vectored Exception Handler
[VEH](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling) is a way to add our own exception handlers in WinAPI. When exception s.a. wrong memory access is encountered, the program calls our specified handler.

The handler is added using WinAPI function `AddVectoredExceptionHandler`.

### Call stask spoofing
When functions are called, they know where to return to from the *stack*. By going through the stack (so called *unwinding*), security products can learn who called some sensitive APIs. If, for example they find that a sensitive operation is performed with weird callstack, they can raise alert. Call stack spoofing is a method of creating fake stack when we call these sensitive APIs, so everything looks in order. However, this has one problem - how does the called function return?

There's lots of [research](https://dtsec.us/2023-09-15-StackSpoofin/) on call stack/return address spoofing so I won't list it here. The one most similar to this technique is the [VulcanRaven](https://github.com/WithSecureLabs/CallStackSpoofer), which also uses VEH. However, using Fibers we can remove the need for creating new threads in this technique.

## The technique
The technique uses two components - fiber and Vectored Exception Handler. We use fiber switch to setup new stack and call the wanted function. The function fails to return in the end, invoking our VEH which switches back to the main fiber, which can seamlessly continue in execution.

First function I will show are our testing functions. These do not really contain anything of interest, but showcase what we want to achieve:
```zig

// The testing function we will call.
// The function returns 0xbeef if the arguments were passed correctly
// and the return address was spoofed
// This helps us test
fn spoofedRetTestHelper(i: u64, j: u64, k: u64, l: u64, m: u64) u64 {
    // ret is the return address
    const ret = @returnAddress();
    // Print for debugging
    std.debug.print("Args: {x},{x},{x},{x},{x}\n", .{ i, j, k, l, m });
    std.debug.print("Return address: 0x{x}\n", .{ret});
    // only if return address is 0 AND all arguments were passed correctly we return 0xbeef
    if (ret == 0 and i == 0xaaaa and j == 0xbbbb and k == 0xcccc and l == 0xdddd and m == 0xeeee) {
        return 0xbeef;
    }

    return 0;
}

test "spoofing works correctly" {
    // We call the function with tuple of arguments
    const returned_value = callFunctionWithSpoofedRet(@ptrCast(&spoofedRetTestHelper), .{ 0xaaaa, 0xbbbb, 0xcccc, 0xdddd, 0xeeee });
    // Check if it really returned 0xbeef, indicating that all args were called correctly
    try std.testing.expectEqual(0xbeef, returned_value);
}
```
The test tests three properties of function `callFunctionWithSpoofedRet`:
1. The function called `spoofedRetTestHelper` with correct arguments.
2. During the call, the return address was correctly spoofed to 0.
3. The return value was extracted correctly.

Let's see the `callFunctionWithSpoofedRet` function. This to function handles the creation of exception handler and the fibers:

```zig

var main_fiber: *anyopaque = undefined;


fn callFunctionWithSpoofedRet(function_ptr: *const anyopaque, arguments: anytype) u64 {
      // 7 is enough for demonstration
    var parameters: [7]u64 = undefined;
    // Param 1 is the function we want to call
    parameters[0] = @intFromPtr(function_ptr);
    // All other params are arguments to the function
    // todo: get the types of different fields and correctly cast them here, so caller does not have to cast everything
    inline for (std.meta.fields(@TypeOf(arguments)), 1..) |field, idx| {
        const value: u64 = @field(arguments, field.name);
        parameters[idx] = value;
    }


    // We setup the VEH, and also make it remove on function return
    const veh_method_ptr: win32.PVECTORED_EXCEPTION_HANDLER = @ptrCast(&vectoredExceptionHandler);
    const veh = win32.AddVectoredExceptionHandler(0, veh_method_ptr);
    defer _ = win32.RemoveVectoredExceptionHandler(veh);

    const fiber_method_ptr: win32.LPFIBER_START_ROUTINE = @ptrCast(&fiberSpoofRet);
    const fiber_ptr = win32.CreateFiber(0, fiber_method_ptr, @ptrCast(&parameters)).?;
    main_fiber = win32.ConvertThreadToFiber(null).?;
    // Stuff happens here
    // 1. Execution is given to the fiber with entrypoint of fiberSpoofRet
    // 2. The wanted function is called
    // 3. Return to 0x0 causes excaption and VEH is invoked
    // 4. VEH saves the return value and exits the fiber
    win32.SwitchToFiber(fiber_ptr);
    // 5. Execution is seamelessly returned here
    _ = win32.ConvertFiberToThread();
    // 6. We return the value
    return return_value;
}

```
First thing to note are arguments to this function - the first argument is function pointer that we want to call. Second argument is a tuple containing arguments to the called function. We then move these arguments into an array of 64-bit integers. I do it this way cause I wanted to try out Zig's variadic functions, but I failed to make it type agnostic.

The interestint stuff happens once the parameters are all in the `parameters` array. We:
1. Add function `vectoredExceptionHandler` as the vectored exception handler.
2. Create fiber that starts at function `fiberSpoofRet` and receives pointer to `parameters`. The handle of this new fiber is `fiber_ptr`.
3. Convert current thread to fiber - this is necessary as you can't switch when you are not in fiber.
4. Call `SwitchToFiber` on `fiber_ptr`, and the execution goes to `fiberSpoofRet`.


The execution continues with the next function. This function just parses the parameters - the function we want to call is at 0, and arguments follow. The inline assembly arranges the stack and registers, then jumps to rbx, where we put the address of called function. We also push 0 to the stack just before jump. This 0 acts as the spoofed return value.
```zig
fn fiberSpoofRet(parameters: [*]u64) void {
    // We support only 6 args, easy to add more if one wants
    const func_addr = parameters[0];
    // Just the x64 windows calling convention
    // https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/windows-x64-calling-convention-stack-frame
    const rcx = parameters[1];
    const rdx = parameters[2];
    const r8 = parameters[3];
    const r9 = parameters[4];
    const stack1 = parameters[5];
    const stack2 = parameters[6];
    _ = asm volatile (
        \\ pushq %[stack2]
        \\ pushq %[stack1]
        \\ pushq %r9
        \\ pushq %r8
        \\ pushq %rdx
        \\ pushq %rcx
        \\ pushq $0
        \\ jmp *%rbx
        : [ret] "={rax}" (-> usize),
        : [_] "{rbx}" (func_addr),
          [_] "{rcx}" (rcx),
          [_] "{rdx}" (rdx),
          [_] "{r8}" (r8),
          [_] "{r9}" (r9),
          [stack1] "r" (stack1),
          [stack2] "r" (stack2),
        : "rbx"
    );
}
```

Once the called function finishes execution, it tries to return to 0, which causes access violation. The exception comes to our exception handler:
```zig
// Return value is global so it can be set from vectored exception handler
var return_value: u64 = undefined;

fn vectoredExceptionHandler(exception_pointers: *win32.EXCEPTION_POINTERS) void {
    const context = exception_pointers.ContextRecord.?;
    // We take the Rax - return value according to x64 calling conv
    // This will not work in Debug mode - Zig's debug mode handles exception and will cause context to be different
    return_value = context.Rax;
    // We switch back to the calling fiber
    win32.SwitchToFiber(main_fiber);
}
```
The exception handler takes the return value from the exception context, saves it to a global variable and switches fiber back to the main fiber. The execution continues back in the `callFunctionWithSpoofedRet` function, where we have only two lines left:
```zig
 
fn callFunctionWithSpoofedRet(function_ptr: *const anyopaque, arguments: anytype) u64 {
    // ...stuff that was explained before...
    // 5. Execution is seamelessly returned here
    _ = win32.ConvertFiberToThread();
    // 6. We return the value
    return return_value;
}
```
The fiber is converted back to thread, and the return value is returned from here. 

Let's look at the actual execution:
![screenshot of output]({{site.url}}/assets/zig03/test_output.png)

### Spoof in practice
I need to try the technique in real world, so I opened up procmon and added opening of registries into our main method. The code is following:
```zig
pub fn main() !void {
    std.debug.print("Hello from main\n", .{});

    const HKEY_CURRENT_USER = win32.HKEY_CURRENT_USER;

    var opened_reg: ?win32.HKEY = undefined;
    _ = win32.RegOpenKeyA(HKEY_CURRENT_USER, "SOFTWARE", @ptrCast(&opened_reg));
    _ = callFunctionWithSpoofedRet(@ptrCast(&win32.RegOpenKeyA), .{ @intFromPtr(HKEY_CURRENT_USER), @intFromPtr("System"), @intFromPtr(&opened_reg) });
}
```

We first open registry SOFTWARE with normal stack, then System with spoofed stack. After execution, we see both call in Procmon output:

![screenshot of procmon]({{site.url}}/assets/zig03/registry_1.png)

The stacktrace of first call contains all functions, including ours:
 
![screenshot of correct stack]({{site.url}}/assets/zig03/correct_stack.png)

The spoofed stack does not unwind properly and ends at the called function, it does not contain our executable:
![screenshot of spoofed stack]({{site.url}}/assets/zig03/spoofed_ret.png)


## Conclusion
I showed that it's possible to use fibers to easily call WinAPI functions and to hide where WinAPI calls come from. Next blog (who knows when though) I'll improve on this PoC and add real call stack obfuscation.

{% include social-media-share.html %}
