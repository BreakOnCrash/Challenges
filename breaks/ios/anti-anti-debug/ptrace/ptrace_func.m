#import <Foundation/Foundation.h>
#import <sys/ptrace.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        ptrace(PT_DENY_ATTACH, 0, 0, 0);
        NSLog(@"Bypass Success! :)");
    }
    return 0;
}