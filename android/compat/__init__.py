import enum
from dataclasses import dataclass, field
from typing import Any, List

try:
    from binaryninja.log import log_debug, log_error, log_info, log_warn  # type: ignore
    from binaryninja.enums import Endianness, InstructionTextTokenType  # type: ignore
    from binaryninja.function import InstructionTextToken  # type: ignore

except ModuleNotFoundError:

    def log_debug(s: str) -> None:
        print(s)


    def log_error(s: str) -> None:
        print(s)


    def log_info(s: str) -> None:
        print(s)


    def log_warn(s: str) -> None:
        print(s)


    # When https://github.com/python/mypy/issues/1153 is fixed, these type
    # ignores should be removed
    class Endianness(enum.Enum):  # type: ignore
        BigEndian = enum.auto()
        LittleEndian = enum.auto()


    @dataclass
    class InstructionTextTokenType:  # type: ignore
        # Text that doesn't fit into the other tokens
        TextToken = enum.auto
        # The instruction mnemonic
        InstructionToken = enum.auto
        # The comma or whatever else separates tokens
        OperandSeparatorToken = enum.auto
        # Registers
        RegisterToken = enum.auto
        # Integers
        IntegerToken = enum.auto
        # Integers that are likely addresses
        PossibleAddressToken = enum.auto
        # The start of memory operand
        BeginMemoryOperandToken = enum.auto
        # The end of a memory operand
        EndMemoryOperandToken = enum.auto
        # Floating point number
        FloatingPointToken = enum.auto


    @dataclass
    class InstructionTextToken:  # type: ignore
        token_type: InstructionTextTokenType
        text: str
        value: int = 0
        size: int = 0
        operand: int = 4294967295
        context = None
        address: int = 0
        confidence: int = 255
        typeNames: List[Any] = field(default_factory=list)
        width: int = 0

__all__ = [
    log_debug,
    log_error,
    log_info,
    log_warn,
    Endianness,
    InstructionTextToken,
    InstructionTextTokenType,
]
