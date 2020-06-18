"""BinaryView class for Binary Ninja plugin."""
import base64
import dataclasses
import json
import pickle
from typing import Any, Set

from binaryninja.binaryview import BinaryView  # type: ignore
from binaryninja.enums import (  # type: ignore
    Endianness,
    SectionSemantics,
    SegmentFlag,
    SymbolType,
)
from binaryninja.log import log_debug, log_error, log_warn  # type: ignore
from binaryninja.platform import Platform  # type: ignore
from binaryninja.plugin import BackgroundTaskThread  # type: ignore
from binaryninja.types import Symbol  # type: ignore

from .android.dex import AccessFlag, DexFile


class DataclassJSONEncoder(json.JSONEncoder):
    def default(self, o: object) -> Any:
        if isinstance(o, bytes):
            return base64.b64encode(o).decode()
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if isinstance(o, AccessFlag):
            return o.value
        return super().default(o)


class JsonWriter(BackgroundTaskThread):  # type: ignore
    def __init__(self, obj: Any, fn: str) -> None:
        BackgroundTaskThread.__init__(self, "Writing Dex structure as JSON")
        self.obj = obj
        self.fn = fn

    def run(self) -> None:
        with open(self.fn + ".pickle", "bw") as fb:
            pickle.dump(self.obj, fb)
        with open(self.fn, "w") as f:
            json.dump(self.obj.__dict__, f, cls=DataclassJSONEncoder)


class DexParser(BackgroundTaskThread):  # type: ignore

    progress_title = "Parsing Dex"

    def __init__(self, bv: BinaryView) -> None:
        BackgroundTaskThread.__init__(self, self.progress_title)
        self.bv = bv

    def run(self) -> None:
        try:
            df = DexFile(self.bv.raw.read(0, self.bv.raw.end))
        except Exception:
            log_error("caught error, writing json anyway")
            raise
        finally:
            # TODO add gui button to do this
            # TODO make this depend on filename
            # FIXME this is a file write -> code exec vuln with the right
            # timing
            background_task = JsonWriter(df, "/tmp/out.json")
            background_task.start()

        data_size = df._parse_uint(self.bv.hdr[104:108])
        data_off = df._parse_uint(self.bv.hdr[108:112])
        self.bv.add_auto_segment(
            data_off,
            data_size,
            data_off,
            data_size,
            SegmentFlag.SegmentReadable
            | SegmentFlag.SegmentContainsData
            | SegmentFlag.SegmentContainsCode,
        )

        # Process classes and code blocks
        # For each code block, add
        # - binja section
        # - binja function
        # - binja symbol
        # - comments for tries and catches
        # TODO figure out where to put static field initializations
        self.progress = self.progress_title + ": processing code blocks"
        defined_functions: Set[str] = set()
        for class_def in df.class_defs:
            if not class_def.class_data:
                continue
            for method in (
                class_def.class_data.direct_methods
                + class_def.class_data.virtual_methods
            ):
                if method.code:
                    off = method.code._insns_off
                    # Add section
                    self.bv.add_auto_section(
                        f"code_{hex(off)}",
                        method.code._insns_off,
                        2 * method.code.insns_size,
                        SectionSemantics.ReadOnlyCodeSectionSemantics,
                    )
                    # Add function and symbol
                    function_name = f"{method.access_flags}{method.method.class_}->{method.method.name}("
                    for param in method.method.proto.parameters:
                        function_name += param
                    function_name += ")" + method.method.proto.return_type
                    if function_name in defined_functions:
                        log_error(f"Duplicate function name {function_name}")
                    defined_functions.add(function_name)
                    self.bv.define_auto_symbol(
                        Symbol(SymbolType.FunctionSymbol, off, function_name)
                    )
                    self.bv.add_function(off)

                    # Add tries and catches as comments
                    if method.code.tries_size:
                        for try_item in method.code.tries:
                            self.bv.set_comment_at(
                                off + try_item.start_addr * 2,
                                f":try_start_{try_item.start_addr:x}",
                            )
                            self.bv.set_comment_at(
                                off + try_item.start_addr * 2 + try_item.insn_count * 2,
                                f":try_end_{try_item.start_addr+try_item.insn_count:x}",
                            )
                            self.bv.set_comment_at(
                                off + try_item.start_addr * 2 + try_item.insn_count * 2,
                                f"{try_item.handler}",
                            )

        # TODO create data sections for static fields


class Dex(BinaryView):  # type: ignore
    name = "Dex"

    DEX_FILE_MAGICS = [b"dex\n039\0", b"dex\n038\0", b"dex\n037\0", b"dex\n035\0"]

    def __init__(self, data: BinaryView) -> None:
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.raw = data

    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        return data.read(0, 8) in cls.DEX_FILE_MAGICS

    def init(self) -> bool:
        """Main function, calls DexParser.run()"""
        self.platform = Platform["Smali"]
        self.hdr = self.raw.read(0, 0x70)
        background_parser = DexParser(self)
        background_parser.start()
        return True

    # def perform_get_address_size(self):
    #     return 2

    def perform_is_executable(self) -> bool:
        return True

    # TODO maybe set this? There is no entry point in this file format, but it
    # could be set to the first function or something
    # def perform_get_entry_point(self):
    #     return self.CODE_OFFSET | 0

    def perform_get_default_endianness(self) -> Endianness:
        return Endianness.LittleEndian
