# coding=utf-8
# https://eternal.red/2018/unicorn-engine-tutorial/#task-4
import struct
from unicorn import *
from unicorn.arm_const import *


def read(name):
    with open(name, 'rb') as f:
        return f.read()


def u32(data):
    return struct.unpack("I", data)[0]


def p32(num):
    return struct.pack("I", num)


stack = []
d = {}
def hook_code(mu, address, size, user_data):
    # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))

    if address == 0x000104D0:
        arg0 = mu.reg_read(UC_ARM_REG_R0)
        if arg0 in d:
            ret = d[arg0]
            mu.reg_write(UC_ARM_REG_R0, ret)
            mu.reg_write(UC_ARM_REG_PC, 0x105BC) # main ret
        else:
            stack.append(arg0)
    elif address == 0x00010580:
        arg0 = stack.pop()
        ret = mu.reg_read(UC_ARM_REG_R0)
        d[arg0] = ret


if __name__ == "__main__":
    mu = Uc(UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)

    BASE = 0x10000
    STACK_ADDR = 0x300000
    STACK_SIZE = 1024*1024

    mu.mem_map(BASE, 1024*1024)
    mu.mem_map(STACK_ADDR, STACK_SIZE)

    mu.mem_write(BASE, read("./task4"))
    mu.reg_write(UC_ARM_REG_SP, STACK_ADDR + int(STACK_SIZE/2))


    mu.hook_add(UC_HOOK_CODE, hook_code)
    # main - 0x00010584
    # call print - 0x000105A8
    mu.emu_start(0x00010584, 0x000105A8)
    return_value = mu.reg_read(UC_ARM_REG_R1)
    print( "The return value is %d" % return_value)
