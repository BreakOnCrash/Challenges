# Anti-Anti-DEBUG - Ptrace

## Practices

### 0x00 ptrace function

```bash
clang -framework Foundation -o out/ptrace-tester ptrace_func.m
```

#### arm

```bash
$ lldb out/ptrace-tester
(lldb) b ptrace                     # 设置 ptrace 断点
(lldb) r                            # 运行
(lldb) reg read                     # 读取寄存器
General Purpose Registers:
        x0 = 0x000000000000001f     # ptrace 第一个参数 0x1f(PT_DENY_ATTACH)
        x1 = 0x0000000000000000
        x2 = 0x0000000000000000
        x3 = 0x0000000000000000
(lldb) reg write x0 0               # 改为 0
(lldb) c                            # 继续运行
...
.......Bypass Success! :)
```

#### x86_64

如果你的系统是arm，那就加上参数 `-arch x86_64` 编译。

```bash
$ lldb out/ptrace-tester
(lldb) b ptrace                     # 设置 ptrace 断点
(lldb) r                            # 运行
(lldb) reg read                     # 读取寄存器
General Purpose Registers:
        rax = 0x0000000000000000
        rbx = 0x0000000108a01bd0
        rcx = 0x0000000000000000
        rdx = 0x0000000000000000
        rdi = 0x000000000000001f    # ptrace 第一个参数 0x1f(PT_DENY_ATTACH)
(lldb) reg w rdi 0                  # 改为 0
(lldb) c                            # 继续运行
...
.......Bypass Success! :)
```

### 0x01 ptrace syscall

asm ptrace syscall 绕过方式也和用户层函数调用一样修改第一个参数，不过断点是要打在 syscall 指令地址处。

tips: 有时不太好找到 syscall 的位置可以试试 s(进入函数)/n(进入函数) 单步调试，或者从反编译里中搜索syscall的指令。

#### arm

```bash
clang -framework Foundation -o out/ptrace-tester ptrace_syscall.m
```

```bash
$ lldb out/ptrace-tester
(lldb) b disableDebugger                        # 断点主函数
(lldb) r                                        # 运行
(lldb) di -n disableDebugger                    # 反编译查看
ptrace-tester`disableDebugger:
->  0x100003efc <+0>:  mov    x3, #0x0
    0x100003f00 <+4>:  mov    x2, #0x0
    0x100003f04 <+8>:  mov    x1, #0x0
    0x100003f08 <+12>: mov    x0, #0x1f
    0x100003f0c <+16>: mov    x16, #0x1a
    0x100003f10 <+20>: svc    #0x80             # 断点断到这个地址
    0x100003f14 <+24>: ret
(lldb) b 0x100003f10                            # 读取寄存器
(lldb) c                                        # 读取寄存器
(lldb) reg write x0 0                           # 改为 0
(lldb) c                                        # 继续运行
...
.......Bypass Success! :)
```

#### x86_64

```bash
clang -arch x86_64 -framework Foundation -o out/ptrace-tester ptrace_syscall.m
```

和上面差不多。

### 0x02 ptrace syscall objc-load

遇到一个有趣的案例：[demo.m](./demo.m)

`+ (void)load` 方法在 Objective-C 中是一个特殊的类方法，它会在类被加载到内存时自动调用。

**执行顺序如下：**
1. 在程序开始执行时，首先加载类 Foo 到内存中。
2. 当类 Foo 被加载到内存中时，+ (void)load 方法自动执行。
3. load 方法内的汇编指令被执行，尝试防止调试器附加。

#### 总结

1. 先设置 main 断点没跑到，进程直接退出：`Process xxx exited with status = 45`。
2. 开始排查加载的第三方库，挨个断点也没看到 `syscall` 的地方。
3. 最后把主 macho 函数都设置下断点，就找到了：

```bash
$lldb  "/Applications/DemoApp.app/Contents/MacOS/DemoApp"
(lldb) b -r . -s DemoApp
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.4791
    frame #0: 0x000000010014b4b0 DemoApp`+[Foo load]
DemoApp`+[Foo load]:
->  0x10014b4b0 <+0>: pushq  %rbp
    0x10014b4b1 <+1>: movq   %rsp, %rbp
    0x10014b4b4 <+4>: movq   %rdi, -0x8(%rbp)
    0x10014b4b8 <+8>: movq   %rsi, -0x10(%rbp)
Target 0: (DemoApp) stopped.
```



## 参考文章
- [Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)
- [Preventing an iOS mobile application from being debugged](https://medium.com/csg-govtech/preventing-an-ios-mobile-application-from-being-debugged-the-secure-way-1094731ff566)
- [A macOS anti-debug technique using ptrace](https://cardaci.xyz/blog/2018/02/12/a-macos-anti-debug-technique-using-ptrace/)