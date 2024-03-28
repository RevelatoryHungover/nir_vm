from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.analysis.simplifier import *
from miasm.arch.nir.regs import *
from miasm.arch.nir.arch import *
import miasm.arch.nir.arch as arch_nir
from miasm.core.utils import *
import subprocess


opcodes = defaultdict()

op_dic = {
    0xcb8 : ["EXIT_REG", reg_idx],
    0xbcc : ["DEC", reg_idx],
    0xd70 : ["RET", ],
    0x6e8 : ["MEMFETCH", reg_idx],
    0xcd8 : ["CALL", imm32],
    0x358 : ["PUTCHAR_REG", reg_idx],
    0x444 : ["JMP", imm32],
    0x980 : ["XOR", ],
    0x8fc : ["MUL", ],
    0x770 : ["AND", ],
    0xb68 : ["INC", reg_idx],
    0x4ac : ["JE", imm32],
    0x67c : ["MEMSTORE", reg_idx],
    0x878 : ["ADD", ],
    0x380 : ["PUSH_IMM", imm32],
    0x3f0 : ["ROMFETCH", reg_idx],
    0x3b0 : ["PUSH_REG", reg_idx],
    0x594 : ["JNE", imm32],
    0xa04 : ["PUTCHAR_IMM", putchar_imm32],
    0xa44 : ["EXIT_IMM", imm32],
    0xa54 : ["MEMSHIFT_IMM", imm32],
    0xaa0 : ["MEMSHIFT_REG", reg_idx],
    0xafc : ["POP", reg_idx],
    0xc30 : ["MOD", reg_idx],
}


def save_ircfg(asmcfg, name):
		open(name, 'w').write(asmcfg.dot())
		subprocess.call(["dot", "-Tpng", name, "-o", name.split('.')[0]+'.png'])








bclist = []
fin = open("nir_bytecode.bin", 'rb')
vm_init_bc = fin.read()
bclist.append(vm_init_bc)




machine = Machine("nir")
addr = 0x0
res_list = []

print("\nLength of VM bytecode = 0x%x" % ( len(bclist[0])//4))

opcodes = defaultdict()

loc_db = LocationDB()
mdis = machine.dis_engine(bclist[0], loc_db=loc_db)
asmcfg = mdis.dis_multiblock(addr)
#asmcfg_dc0 = mdis.dis_multiblock(0xdc0)
res_list.append([loc_db, asmcfg])
save_ircfg(asmcfg, "output/nir_asmcfg%s.dot"%str(0+1))
#save_ircfg(asmcfg_dc0, "output/nir_asmcfg_dc0_%s.dot"%str(i+1))


#print(res_list)
nl = 0
# saving the simplified IR for a specific level
loc_db = res_list[nl][0]
asmcfg = res_list[nl][1]

ira = machine.ira(loc_db)
ircfg = ira.new_ircfg_from_asmcfg(asmcfg)
from miasm.ir.symbexec import SymbolicExecutionEngine
sb = SymbolicExecutionEngine(ira)
sb.symbols[machine.mn.regs.R1] = ExprInt(0xDEADBEEC, 32)
sb.symbols[machine.mn.regs.R0] = ExprInt(0x0, 32)
#symbolic_pc = sb.run_at(ircfg, 0)
symbolic_pc = sb.run_at(ircfg, 0, step=True)
print(symbolic_pc)
save_ircfg(ircfg, "output/nir_ircfg%s.dot"%str(nl+1))

loc = loc_db.get_offset_location(addr)

simp = IRCFGSimplifierCommon(ira)
simp.simplify(ircfg, loc)
save_ircfg(ircfg, "output/nir_ircfg_simp_common%s.dot"%str(nl+1))

simp = IRCFGSimplifierSSA(ira)
simp.simplify(ircfg, loc)
save_ircfg(ircfg, "output/nir_ircfg_simp_ssa%s.dot"%str(nl+1))
