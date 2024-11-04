# coding=utf-8
# https://eternal.red/2018/unicorn-engine-tutorial/#task-1
import struct
from unicorn import *
from unicorn.x86_const import *


def read(name):
    with open(name, 'rb') as f:
        return f.read()


def u32(data):
    return struct.unpack("I", data)[0]


def p32(num):
    return struct.pack("I", num)


if __name__ == "__main__":
    # x64
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    # elf base address
    BASE = 0x400000
    STACK_ADDR = 0x0
    STACK_SIZE = 1024*1024

    mu.mem_map(BASE, 1024*1024)
    mu.mem_map(STACK_ADDR, STACK_SIZE)

    mu.mem_write(BASE, read("./fibonacci"))
    # 指到栈底
    mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 1)

    # 避免重复计算
    stack = []
    d = {}

    # 因为用了libc的函数，而这里没加载，直接跳过
    instructions_skips = [
        0x00000000004004EF,
        0x00000000004004F6,
        0x0000000000400502,
        0x000000000040054F]

    FIBONACCI_ENTRY = 0x0000000000400670
    FIBONACCI_END = [0x00000000004006F1, 0x0000000000400709]

    def hook_code(mu, address, size, user_data):
        # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %
        #       (address, size))

        if address in instructions_skips:
            mu.reg_write(UC_X86_REG_RIP, address+size)  # RIP 到下个指令

        elif address == 0x400560:  # call    __IO_putc 打印flag
            c = mu.reg_read(UC_X86_REG_RDI)  # the first argument 即是输入参数
            print(chr(c))
            mu.reg_write(UC_X86_REG_RIP, address+size)

        # 读取函数的两个参数（RDI 和 RSI 寄存器），并检查是否已经计算过相同参数的结果
        elif address == FIBONACCI_ENTRY:
            arg0 = mu.reg_read(UC_X86_REG_RDI)
            r_rsi = mu.reg_read(UC_X86_REG_RSI)
            arg1 = u32(mu.mem_read(r_rsi, 4))

            # print("FIBONACCI_ENTRY", arg0, arg1)

            if (arg0, arg1) in d:
                (ret_rax, ret_ref) = d[(arg0, arg1)]
                mu.reg_write(UC_X86_REG_RAX, ret_rax)
                mu.mem_write(r_rsi, p32(ret_ref))
                mu.reg_write(UC_X86_REG_RIP, 0x400582) # TODO  -> main retn
                # print("return")
            else:
                stack.append((arg0, arg1, r_rsi))

        elif address in FIBONACCI_END:
            (arg0, arg1, r_rsi) = stack.pop()

            ret_rax = mu.reg_read(UC_X86_REG_RAX)
            ret_ref = u32(mu.mem_read(r_rsi, 4))

            # print("FIBONACCI_END", arg0, arg1, ret_rax, ret_ref)

    mu.hook_add(UC_HOOK_CODE, hook_code)
    # main function
    mu.emu_start(0x00000000004004E0, 0x0000000000400575)
