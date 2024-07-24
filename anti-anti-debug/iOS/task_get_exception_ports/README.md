# Anti-Anti-DEBUG - task_get_exception_ports

> https://opensource.apple.com/source/xnu/xnu-7195.60.75/osfmk/man/task_get_exception_ports.html
> https://opensource.apple.com/source/xnu/xnu-7195.60.75/osfmk/mach/exception_types.h.auto.html

在 iOS 和 Mac OS 中，当程序在调试器下运行时，会使用异常端口，应用程序使用此方法检索当前任务正在处理的异常列表。

检测示例：

```c
// clang -o main main.c
#include <stdlib.h>
#include <stdio.h>
#include <mach/mach.h>

int main(int argc, const char * argv[]) {
	exception_mask_t       exception_masks[EXC_TYPES_COUNT];
	mach_msg_type_number_t exception_count = 0;
	mach_port_t            exception_ports[EXC_TYPES_COUNT];
	exception_behavior_t   exception_behaviors[EXC_TYPES_COUNT];
	thread_state_flavor_t  exception_flavors[EXC_TYPES_COUNT];

	kern_return_t kr = task_get_exception_ports(
		mach_task_self(),
		// In earlier header versions EXC_MASK_ALL could have been used, but it now includes too much.
		EXC_MASK_BAD_ACCESS
		| EXC_MASK_BAD_INSTRUCTION
		| EXC_MASK_ARITHMETIC
		| EXC_MASK_EMULATION
		| EXC_MASK_SOFTWARE
		| EXC_MASK_BREAKPOINT
		| EXC_MASK_SYSCALL
		| EXC_MASK_MACH_SYSCALL
		| EXC_MASK_RPC_ALERT
		| EXC_MASK_CRASH
		,
		exception_masks,
		&exception_count,
		exception_ports,
		exception_behaviors,
		exception_flavors
	);
	if (kr == KERN_SUCCESS) {
		for (mach_msg_type_number_t i = 0; i < exception_count; i++) {
			if (MACH_PORT_VALID(exception_ports[i])) {
				printf("DEBUGGER DETECTED!\n");
				return 1;
			}
		}
	}
	else {
		printf("ERROR: task_get_exception_ports: %s\n", mach_error_string(kr));
		return 1;
	}

	printf("No debugger detected\n");

	return 0;
}
```

## Blog
- https://alexomara.com/blog/defeating-anti-debug-techniques-macos-mach-exception-ports/