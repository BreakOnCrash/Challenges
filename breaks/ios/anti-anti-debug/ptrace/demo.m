#import <Foundation/Foundation.h>

@interface Foo : NSObject
@end

@implementation Foo
+ (void)load {
  asm("movq $0, %rcx");
  asm("movq $0, %rdx");
  asm("movq $0, %rsi");
  asm("movq $0x1f, %rdi");      /* PT_DENY_ATTACH 31 (0x1f)*/
  asm("movq $0x200001a, %rax"); /* ptrace syscall number 26 (0x1a) */
  asm("syscall");
}
@end

int main(int argc, const char *argv[]) {
  NSLog(@"Bypass Success! :)");
  return 0;
}