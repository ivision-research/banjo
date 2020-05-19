#!/usr/bin/env python3.8
import argparse
from pathlib import Path
from typing import TextIO

from android.dex import DexClassDef, DexEncodedMethod, DexFile, FileOffset
from android.smali import disassemble, endian_swap_shorts

THROW = False


def write_method(df: DexFile, f: TextIO, meth: DexEncodedMethod) -> None:
    f.write(
        f'\n.method {meth.access_flags}{meth.method.name}({"".join(meth.method.proto.parameters)}){meth.method.proto.return_type}\n    .registers {meth.code.registers_size if meth.code else 0}\n'
    )
    i = 0
    while meth.code and i < len(meth.code.insns):
        try:
            insns, size = disassemble(
                df,
                endian_swap_shorts(meth.code.insns[i:]),
                FileOffset(meth.code._insns_off + i),
            )
            f.write(f'\n    {"".join([insn.text for insn in insns])}\n')
            i += size
        except Exception as e:
            print(
                f"Failed to disassemble {endian_swap_shorts(meth.code.insns[i:])!r} at {hex(meth.code._insns_off + i)}: {e}"
            )
            if THROW:
                raise e
            f.write(
                f"\n    Failed to disassemble: {endian_swap_shorts(meth.code.insns[i:])!r}: {e}\n"
            )
            i += 2
    f.write(".end method\n")


def write_class(df: DexFile, pth: Path, cls: DexClassDef) -> None:
    with pth.open("w") as f:
        f.write(
            f'.class {cls.access_flags}{cls.class_type}\n.super {cls.superclass}\n.source "{cls.source_file}"\n\n'
        )
        if not cls.class_data:
            return
        if cls.class_data.direct_methods:
            f.write("\n# direct methods")
        for dm in cls.class_data.direct_methods:
            write_method(df, f, dm)
        if cls.class_data.virtual_methods:
            f.write("\n# virtual methods")
        for vm in cls.class_data.virtual_methods:
            write_method(df, f, vm)


def dis_file(fn: str, out_dir: str = "out") -> None:
    with open(fn, "br") as f:
        df = DexFile(f.read())
    out = Path(out_dir)
    for cls in df.class_defs:
        if not cls.class_type.startswith("L"):
            print("idk what to do with {cls.class_type=}")
        class_path = Path(cls.class_type[1:-1])
        class_dir = out / class_path.parent
        class_dir.mkdir(parents=True, exist_ok=True)
        write_class(df, class_dir / class_path.with_suffix(".smali").name, cls)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Disassemble dex file.")
    parser.add_argument(
        "dex_filename", type=Path, help="Filename of dex to disassemble"
    )
    parser.add_argument(
        "-o",
        dest="out_dir",
        default=Path("out/"),
        type=Path,
        help="directory to write output to (default: out/)",
    )
    parser.add_argument(
        "-t",
        dest="throw",
        action="store_false",
        help="throw exception on first disassembly error",
    )

    args = parser.parse_args()
    if not args.dex_filename.exists():
        parser.error(f"the file '{args.dex_filename}' does not exist.")
    THROW = args.throw
    dis_file(args.dex_filename, args.out_dir)
