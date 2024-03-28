from miasm.core.asmblock import disasmEngine
from miasm.arch.nir.arch import mn_nir


cb_nir_funcs = []


def cb_nir_disasm(mdis, cur_block, offset_to_dis):
    for func in cb_nir_funcs:
        func(mdis, cur_block, offset_to_dis)


class dis_nir(disasmEngine):
    attrib = None

    def __init__(self, bs=None, **kwargs):
        super(dis_nir, self).__init__(mn_nir, self.attrib, bs, **kwargs)
        self.dis_block_callback = cb_nir_disasm