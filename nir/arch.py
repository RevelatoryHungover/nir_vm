from miasm.core.cpu import *
from miasm.core.utils import Disasm_Exception
from miasm.expression.expression import ExprId, ExprInt, ExprLoc, \
    ExprMem, ExprOp, is_expr
from miasm.core.asm_ast import AstId, AstMem
from miasm.arch.nir.regs import *
import miasm.arch.nir.regs as nir_regs_module
from pyparsing import *

conditional_branch = ["JE","JNE"]
unconditional_branch = ["JMP"]

call_instr = ["CALL"]
breakflow = ["EXIT"]+conditional_branch+unconditional_branch+["RET"]

class bs32(bs):
    prio = default_prio

    def __init__(self, v, cls=None, fname=None, **kargs):
        super(bs32, self).__init__(int2bin(swap32(v), 32), 32,
                                  cls=cls, fname=fname, **kargs)

class instruction_nir(instruction):
  """Generic nir instruction
  """
  delayslot = 0

  def __init__(self, name, mode, args, additional_info=None):
    self.name = name
    self.mode = mode
    self.args = args
    self.additional_info = additional_info
    self.offset = None
    self.l = None
    self.b = None


  @staticmethod
  def arg2str(expr, pos=None, loc_db=None):
      """Convert mnemonics arguments into readable strings according to the
      nir architecture and their internal types
      """

      if isinstance(expr, ExprId) or isinstance(expr, ExprInt):
          return str(expr)

      elif isinstance(expr, ExprLoc):
          if loc_db is not None:
              return loc_db.pretty_str(expr.loc_key)
          else:
              return str(expr)
      return str(expr)

  def to_string(self, loc_db=None):
    #print(hex(self.offset))
    return super(instruction_nir, self).to_string(loc_db)
  
  def fixDstOffset(self):
    expr = self.args[self.get_dst_num()]
    if expr.is_int():
      return
    self.args[self.get_dst_num()] = ((int(expr)*4)+self.offset + 8) & 0xffffffff

  def breakflow(self):
    """Instructions that stop a basic block."""
    if self.name in breakflow:
      return True

    return self.name in ['CALL']

  def splitflow(self):
    """Instructions that splits a basic block, i.e. the CPU can go somewhere else."""
    if self.name in conditional_branch:
        return True
    if self.name in unconditional_branch:
        return False
    return self.name in ['CALL']

  def dstflow(self):
    """Instructions that explicitly provide the destination."""
    if self.name in conditional_branch+unconditional_branch:
      return True
    return self.name in ['CALL']

  def dstflow2label(self, loc_db):
    """Set the label for the current destination.
        Note: it is used at disassembly"""

    loc_arg = self.get_dst_num()
    expr = self.args[loc_arg]
    if not expr.is_int():
      return
    addr = ((int(expr)*4)+self.offset + 8) & 0xffffffff
    loc_key = loc_db.get_or_create_offset_location(addr)
    self.args[0] = ExprLoc(loc_key, expr.size)

  def getdstflow(self, loc_db):
    """Get the argument that points to the instruction destination."""
    if self.name in conditional_branch+call_instr+unconditional_branch:
      return [self.args[0]]
    raise RuntimeError

  def is_subcall(self):
    """
    Instructions used to call sub functions.
    """
    return self.name in ['CALL']

  def get_dst_num(self):
    return 0

class nir_additional_info(object):
  """Additional nir instructions information
  """

  def __init__(self):
    self.except_on_instr = False

class mn_nir(cls_mn):
  num = 0  # holds the number of mnemonics
  all_mn = list()  # list of mnenomnics, converted to metamn objects
  all_mn_mode = defaultdict(list) # mneomnics, converted to metamn objects
  all_mn_name = defaultdict(list) # mnenomnics strings
  all_mn_inst = defaultdict(list) # mnemonics objects
  bintree = dict()  # Variable storing internal values used to guess a
  instruction = instruction_nir
  regs = nir_regs_module
  max_instruction_len = 8
  delayslot = 0
  name = "nir"

  def additional_info(self):
    return nir_additional_info()

  @classmethod
  def gen_modes(cls, subcls, name, bases, dct, fields):
    dct["mode"] = None
    return [(subcls, name, bases, dct, fields)]

  @classmethod
  def getmn(cls, name):
    return name.upper()

  @classmethod
  def getpc(cls, attrib=None):
    """"Return the ExprId that represents the Program Counter.
    Notes:
        - mandatory for the symbolic execution
        - PC is defined in regs.py
    """
    return PC

  @classmethod
  def getsp(cls, attrib=None):
    """"Return the ExprId that represents the Stack Pointer.
    Notes:
        - mandatory for the symbolic execution
        - SP is defined in regs.py
    """
    return SP

def addop(name, fields, args=None, alias=False):
  """
  Dynamically create the "name" object
  Notes:
      - it could be moved to a generic function such as:
        addop(name, fields, cls_mn, args=None, alias=False).
      - most architectures use the same code
  Args:
      name:   the mnemonic name
      fields: used to fill the object.__dict__'fields' attribute # GV: not understood yet
      args:   used to fill the object.__dict__'fields' attribute # GV: not understood yet
      alias:  used to fill the object.__dict__'fields' attribute # GV: not understood yet
  """

  namespace = {"fields": fields, "alias": alias}

  if args is not None:
      namespace["args"] = args

  # Dynamically create the "name" object
  type(name, (mn_nir,), namespace)

class nir_arg(m_arg):
  def asm_ast_to_expr(self, arg, loc_db):
    """Convert AST to expressions
       Note: - Must be implemented"""

    if isinstance(arg, AstId):
      if isinstance(arg.name, ExprId):
        return arg.name
      if isinstance(arg.name, str) and arg.name in gpr_names:
        return None  # GV: why?
      loc_key = loc_db.get_or_create_name_location(arg.name.encode())
      return ExprLoc(loc_key, 64)

    elif isinstance(arg, AstMem):
      addr = self.asm_ast_to_expr(arg.ptr, loc_db)
      if addr is None:
        return None
      return ExprMem(addr, 64)

    elif isinstance(arg, AstInt):
      return ExprInt(arg.value, 64)

    elif isinstance(arg, AstOp):
      args = [self.asm_ast_to_expr(tmp, loc_db) for tmp in arg.args]
      if None in args:
          return None
      return ExprOp(arg.op, *args)

    # Raise an exception if the argument was not processed
    message = "mep_arg.asm_ast_to_expr(): don't know what \
                to do with a '%s' instance." % type(arg)
    raise Exception(message)

class nir_reg(reg_noarg, nir_arg):
  """Generic nir register
  Note:
      - the register size will be set using bs()
  """
  reg_info = reg_infos  # the list of nir registers defined in regs.py
  parser = reg_info.parser  # GV: not understood yet



class nir_reg_idx(nir_arg):

  reg_info = reg_infos  # the list of nir registers defined in regs.py
  intsize = 32
  intmask = (1 << intsize) - 1

  def decode(self, v):
    v = swap_sint(self.l, v) & self.intmask 
    v = v&0x3f
    if v >= len(self.reg_info.expr):
      return False
    self.expr = self.reg_info.expr[v]
    return True


class nir_putchar_imm32(imm_noarg, nir_arg):
  intmask = 0xff
  
  def decodeval(self, v):
    return (swap_sint(self.l, v)) & self.intmask 


class nir_imm8(imm_noarg, nir_arg):
  """Generic nir immediate
  Note:
      - the immediate size will be set using bs()
  """
  intsize = 8
  intmask = (1 << intsize) - 1
  parser = base_expr

class nir_imm16(imm_noarg, nir_arg):
  """Generic nir immediate
  Note:
      - the immediate size will be set using bs()
  """
  intsize = 16
  intmask = (1 << intsize) - 1
  parser = base_expr

  def decodeval(self, v):
    return swap_sint(self.l, v) & self.intmask

  def encodeval(self, v):
    return swap_sint(self.l, v) & self.intmask

class nir_imm32(imm_noarg, nir_arg):
  """Generic nir immediate
  Note:
      - the immediate size will be set using bs()
  """
  intsize = 32
  intmask = (1 << intsize) - 1
  parser = base_expr

  def decodeval(self, v):
    return swap_sint(self.l, v) & self.intmask 

  def encodeval(self, v):
    return swap_sint(self.l, v) & self.intmask

class nir_imm64(imm_noarg, nir_arg):
  """Generic nir immediate
  Note:
      - the immediate size will be set using bs()
  """
  intsize = 64
  intmask = (1 << intsize) - 1
  parser = base_expr

  def decodeval(self, v):
    return swap_sint(self.l, v) & self.intmask

  def encodeval(self, v):
    return swap_sint(self.l, v) & self.intmask

reg   = bs(l=32,   cls=(nir_reg, ))
imm8  = bs(l=8,   cls=(nir_imm8,  nir_arg))
imm16 = bs(l=16,  cls=(nir_imm16, nir_arg))
imm32 = bs(l=32,  cls=(nir_imm32, nir_arg))
imm64 = bs(l=64,  cls=(nir_imm64, nir_arg))

reg_idx = bs(l=32,   cls=(nir_reg_idx,  nir_arg))
putchar_imm32 = bs(l=32,   cls=(nir_putchar_imm32,  nir_arg))





#addop("MEMSHIFT_IMM", [bs32(0xba1116a9), imm32, ])
addop("PUSH_REG",     [bs32(0x68), reg_idx, ] )
addop("POP",          [bs32(0x67), reg_idx] )
addop("PUSH_IMM",     [bs32(0x69), imm32, ] )
#addop("MEMSHIFT_REG", [bs32(0x1f0a8e6f), reg_idx, ])
#addop("ROMFETCH",     [bs32(0x8d67bae1), reg_idx, ])
addop("ADD",          [bs32(0x33),imm32])
#addop("MEMSTORE",     [bs32(0xfb521a9c), reg_idx])
addop("JE",           [bs32(0x73), imm32])
addop("JNE",           [bs32(0x74), imm32])
#addop("INC",          [bs32(0xf00bb6c1), reg_idx])
addop("CALL",         [bs32(0xEB), imm32])
addop("JMP",          [bs32(0x72), imm32])
addop("EXIT",     [bs32(0xcc),imm32])
#addop("PUTCHAR_REG",  [bs32(0xd1450d67), reg_idx])
addop("SUB",          [bs32(0x32), imm32])
addop("XOR",          [bs32(0x88), imm32])
addop("DIV",          [bs32(0x34), imm32])
addop("MUL",          [bs32(0x35), imm32])
addop("MOV0",         [bs32(0x678), imm32])
#addop("JNE",          [bs32(0x5a0f38fc), imm32])
#addop("EXIT_REG",     [bs32(0x818cd6b5), reg_idx])
#addop("MOD",          [bs32(0x43ae1f53), reg_idx])
addop("RET",          [bs32(0x50), ])
"""      
} mnemonics;
int bytecode[] = {
  PUSH, input,
  MOV0, 0x2222,
  SUB, 45,
  MOV0, 23,
  ADD,9,
  MOV0, 7,
  MUL, 7,
  DIV,7,
  POP,
  CALL,1,
  EXIT,
  SUB,31337,
  RET
}; 
typedef enum {
		PUSH = 0x68,
		POP = 0x67,
		ADD = 0x33,
		SUB = 0x32,
		DIV = 0x34,
		MUL = 0x35,
        MOV0=0x678,
        MOV1=0x354,
        CALL = 0xEB,
        RET = 0x50,
		EXIT = 0xcc,
   



"""
