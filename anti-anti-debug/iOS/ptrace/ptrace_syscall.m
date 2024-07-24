#import <Foundation/Foundation.h>

void disableDebugger() {
    #ifdef X86_64
        asm("movq $0, %rcx");
        asm("movq $0, %rdx");
        asm("movq $0, %rsi");
        asm("movq $0x1f, %rdi");      /* PT_DENY_ATTACH 31 (0x1f)*/
        asm("movq $0x200001a, %rax"); /* ptrace syscall number 26 (0x1a) */
        asm("syscall");
    #else
        asm("mov x3, #0");
        asm("mov x2, #0");
        asm("mov x1, #0");
        asm("mov x0, #31");  /* PT_DENY_ATTACH 31 (0x1f)*/
        asm("mov x16, #26"); /* ptrace syscall number 26 (0x1a) */
        asm("svc #0x80");
    #endif
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        disableDebugger();
        NSLog(@"Bypass Success! :)");
    }
    return 0;
}