"""Architecture class for Binary Ninja plugin."""

import time
from typing import List, Tuple, cast

from binaryninja.architecture import Architecture  # type: ignore
from binaryninja.enums import BranchType  # type: ignore
from binaryninja.function import (  # type: ignore
    InstructionInfo,
    InstructionTextToken,
    RegisterInfo,
)
from binaryninja.lowlevelil import (  # type: ignore
    LLIL_TEMP,
    LowLevelILFunction,
    LowLevelILOperation,
)

from .android.compat import log_debug, log_error, log_warn
from .android.dex import DexFile, FileOffset
from .android.smali import (
    SmaliFillArrayDataPayload,
    SmaliPackedSwitchPayload,
    SmaliSparseSwitchPayload,
    disassemble,
    endian_swap_shorts,
    load_insns,
    parse_with_format,
    sign,
)


class Smali(Architecture):  # type: ignore
    """Architecture class for disassembling Dalvik bytecode into Smali

    Initializing the class calls android.smali.load_insns(), which imports
    cached instruction information from "android/instruction_data.pickle".

    The three mandatory Architecture functions are implemented:
        - get_instruction_info
        - get_instruction_text
        - get_instruction_low_level_il

    There is also load_dex(), which is called at the beginning of all three
    functions. It grabs the reference to the DexFile in view.
    """

    name = "Smali"

    # FIXME there should be 65536 registers, but binja hangs when the number gets above a thousand or so
    regs = dict(
        {f"v{i}": RegisterInfo(f"v{i}", 4) for i in range(256)},
        pc=RegisterInfo("pc", 4),
        fp=RegisterInfo("fp", 4),
        sp=RegisterInfo("sp", 4),
    )
    stack_pointer = "sp"
    max_instr_length = 200
    instr_alignment = 2

    def __init__(self) -> None:
        self.insns = load_insns()
        super().__init__()

    def load_dex(self) -> None:
        """Set self.df to DexFile of focused file."""
        self.df: DexFile = Architecture["Smali"].dfs[Architecture["Smali"].frame]

    def get_instruction_info(self, data: bytes, addr: FileOffset) -> InstructionInfo:
        self.load_dex()
        ii = InstructionInfo()

        # Handle pseudoinstructions
        if data[0] == 0 and data[1] != 0:
            if data[1] > 3:
                ii.length = 2
                return ii
            ii.length = min(
                self.max_instr_length, self.df.pseudoinstructions[addr]._total_size
            )
            ii.add_branch(BranchType.FunctionReturn)
            return ii

        # Handle normal instructions
        insn_info = self.insns[data[0]]
        ii.length = insn_info.fmt.insn_len * 2

        if insn_info.mnemonic.startswith("return"):
            ii.add_branch(BranchType.FunctionReturn)
        elif insn_info.mnemonic == "throw":
            ii.add_branch(BranchType.ExceptionBranch)
            # TODO
        elif insn_info.mnemonic.startswith("goto"):
            data_to_parse = endian_swap_shorts(data[: 2 * insn_info.fmt.insn_len])
            args = parse_with_format(data_to_parse, insn_info.fmt.format_)
            offset = sign(args["A"], insn_info.fmt.format_.count("A"))
            ii.add_branch(BranchType.UnconditionalBranch, target=addr + offset * 2)
        elif (
            insn_info.mnemonic == "packed-switch"
            or insn_info.mnemonic == "sparse-switch"
        ):
            data_to_parse = endian_swap_shorts(data[: 2 * insn_info.fmt.insn_len])
            args = parse_with_format(data_to_parse, insn_info.fmt.format_)
            offset = sign(args["B"], insn_info.fmt.format_.count("B"))
            ii.add_branch(BranchType.UnresolvedBranch)
            # Adding more than 2 branches causes binja to segfault, so this has
            # to be handled in LLIL instead.
        elif insn_info.mnemonic == "fill-array-data":
            data_to_parse = endian_swap_shorts(data[: 2 * insn_info.fmt.insn_len])
            args = parse_with_format(data_to_parse, insn_info.fmt.format_)
            offset = sign(args["B"], insn_info.fmt.format_.count("B"))
            ii.add_branch(BranchType.TrueBranch, target=addr + offset * 2)
            ii.add_branch(
                BranchType.FalseBranch, target=addr + insn_info.fmt.insn_len * 2
            )
        elif insn_info.mnemonic.startswith("if-"):
            data_to_parse = endian_swap_shorts(data[: 2 * insn_info.fmt.insn_len])
            args = parse_with_format(data_to_parse, insn_info.fmt.format_)
            var = "C" if "C" in args else "B"
            offset = sign(args[var], insn_info.fmt.format_.count(var))
            ii.add_branch(BranchType.TrueBranch, target=addr + offset * 2)
            ii.add_branch(
                BranchType.FalseBranch, target=addr + insn_info.fmt.insn_len * 2
            )
        elif insn_info.mnemonic.startswith("invoke-"):
            if insn_info.mnemonic.startswith("invoke-custom"):
                log_warn("Resolution of invoke-custom is not implemented")
                ii.add_branch(BranchType.UnresolvedBranch)
            else:
                data_to_parse = endian_swap_shorts(data[: 2 * insn_info.fmt.insn_len])
                args = parse_with_format(data_to_parse, insn_info.fmt.format_)
                meth = self.df.method_ids[args["B"]]
                if meth._insns_off is not None:
                    ii.add_branch(BranchType.CallDestination, target=meth._insns_off)
        return ii

    def get_instruction_text(
        self, data: bytes, addr: FileOffset
    ) -> Tuple[List[InstructionTextToken], int]:
        self.load_dex()
        return disassemble(self.df, data, addr)

    def get_instruction_low_level_il(
        self, data: bytes, addr: FileOffset, il: LowLevelILFunction
    ) -> int:
        self.load_dex()
        insn_info = self.insns[data[0]]
        # if data[0] == 0x2B or data[0] == 0x2C and False:
        #     data_to_parse = endian_swap_shorts(data[: 2 * insn_info.fmt.insn_len])
        #     args = parse_with_format(data_to_parse, insn_info.fmt.format_)
        #     offset = sign(args["B"], insn_info.fmt.format_.count("B"))
        #     branches = list()  # [addr + offset * 2, addr + insn_info.fmt.insn_len * 2]
        #     if data[0] == 0x2B:  # packed-switch
        #         payload = cast(
        #             SmaliPackedSwitchPayload,
        #             self.df.pseudoinstructions[cast(FileOffset, addr + offset * 2)],
        #         )
        #         for i in range(len(payload.targets)):
        #             key = payload.first_key + i
        #             target_addr = addr + payload.targets[i] * 2
        #             label = il.get_label_for_address(self, target_addr)
        #             if label is None:
        #                 il.add_label_for_address(self, target_addr)
        #                 label = il.get_label_for_address(self, target_addr)
        #             branches.append(label)
        #     else:  # sparse-switch
        #         log_error("NOT IMPLEMENTED YET")
        #         # for key, target in zip(payload.keys, payload.targets):
        #         #     branches.append(addr + target * 2)
        #     log_warn(f'{branches=}')
        #     reg=il.add(4, il.reg(4, f'v{args["A"]}'), il.const(4, 1))
        #     branches_list = il.add_label_list(branches)
        #     expr=il.expr(LowLevelILOperation.LLIL_JUMP_TO, reg, branches) #, size=insn_info.fmt.insn_len * 2))
        #     il.append(expr)
        expr = il.expr(LowLevelILOperation.LLIL_UNDEF, size=insn_info.fmt.insn_len * 2)
        il.append(expr)
        return insn_info.fmt.insn_len * 2
