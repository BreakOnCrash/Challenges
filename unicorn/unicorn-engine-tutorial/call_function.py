# coding=utf-8
# https://eternal.red/2018/unicorn-engine-tutorial/#task-3
import struct
from unicorn import *
from unicorn.x86_const import *


def read(name):
    with open(name, 'rb') as f:
        return f.read()


def p32(num):
    return struct.pack("I", num)


if __name__ == "__main__":
    BASE = 0x400000
    STACK_ADDR = 0x0
    STACK_SIZE = 1024 * 1024

    # x86
    mu = Uc(UC_ARCH_X86, UC_MODE_32)

    BASE = 0x400000
    STACK_ADDR = 0x0
    STACK_SIZE = 1024*1024

    mu.mem_map(BASE, 1024*1024)
    mu.mem_map(STACK_ADDR, STACK_SIZE)

    mu.mem_write(BASE, read("./function"))
    r_esp = STACK_ADDR + int(STACK_SIZE/2)

    STRING_ADDR = 0x0
    mu.mem_write(STRING_ADDR, b"batman\x00")

    mu.reg_write(UC_X86_REG_ESP, r_esp)
    mu.mem_write(r_esp+4, p32(5))
    mu.mem_write(r_esp+8, p32(STRING_ADDR))

    # super_function 起始地址：
    mu.emu_start(BASE+0x57B, BASE+0x5B1)
    return_value = mu.reg_read(UC_X86_REG_EAX)
    print("The returned value is: %d" % return_value)
