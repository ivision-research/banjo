#!/usr/bin/env python3
"""Generate Dalvik instruction database

If you aren't developing this plugin, you should not need to run this.
"""
import http.client
from html.parser import HTMLParser
from pickle import dump
from typing import Dict, List, Optional, SupportsInt, Tuple, Union, cast

try:
    from .smali import SmaliInstructionFormat, SmaliInstructionInfo, INSTRUCTIONS_PICKLE_PATH
except ModuleNotFoundError:
    from smali import (  # type: ignore
        SmaliInstructionFormat,
        SmaliInstructionInfo,
        INSTRUCTIONS_PICKLE_PATH,
    )


class TableParser(HTMLParser):
    def __init__(self, class_: str) -> None:
        self.nest = 0
        self.table: List[List[str]] = list()
        self.row: List[str] = list()
        self.cell = ""
        self.class_ = class_
        # Assume rowspan is only in first column
        self.rowspan = 0
        super().__init__()

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag == "table" and attrs[0] == ("class", self.class_):
            self.nest = 1
        elif self.nest == 1 and tag in ("tbody", "thead"):
            self.nest = 2
        elif self.nest == 2 and tag == "tr":
            self.nest = 3
        elif self.nest == 3 and tag == "td":
            self.nest = 4
            if len(attrs) and attrs[0][0] == "rowspan":
                self.rowspan = int(cast(Union[str, SupportsInt], attrs[0][1])) - 1

    def handle_endtag(self, tag: str) -> None:
        if self.nest > 0 and tag in ("table", "tbody", "tr", "td"):
            self.nest -= 1
            if tag == "tr":
                if self.row:
                    self.table.append(self.row)
                    self.row = list()
                    if self.rowspan > 0:
                        self.row.append(self.table[-1][0])
                        self.rowspan -= 1
            elif tag == "td":
                self.row.append(self.cell.strip())
                self.cell = ""

    def handle_data(self, data: str) -> None:
        if self.nest == 4:
            self.cell += data


def parse_syntax(cell: str, opcode: int = None) -> Tuple[str, str]:
    if cell == "(unused)":
        return "", ""
    elif opcode is None:
        if " " in cell:
            if "(" in cell:
                # Remove '(with supplemental data as specified below in "fill-array-data-payload Format")'
                cell = cell[: cell.find("(")]
            return cell[: cell.find(" ")], cell[cell.find(" ") + 1 :]
        else:
            # Just mnemonic, no args
            return cell, ""
    else:
        header = ""
        for line in cell.split("\n"):
            if line.startswith(" "):
                if int(line[4:6], 16) == opcode:
                    return line[8:], header[header.find(" ") + 1 :]
            else:
                header = line
    raise ValueError("Failed to find opcode")


def parse_row(
    row: List[str], formats: Dict[str, SmaliInstructionFormat], opcode: int = None
) -> SmaliInstructionInfo:
    formatid = row[0].split(" ")[1]
    mnemonic, syntax = parse_syntax(row[1], opcode)
    insn = SmaliInstructionInfo(
        _opcode=opcode if opcode is not None else int(row[0][:2], 16),
        _formatid=formatid,
        fmt=formats[formatid],
        mnemonic=mnemonic,
        syntax=syntax,
        arguments=row[2],
        description=row[3],
    )
    return insn


def gen_instruction_info() -> None:
    # This should use the real site, but there are some HTML bugs in the live version. There's a PR open internally at Google to fix these. FIXME
    # conn = http.client.HTTPSConnection("source.android.com")
    # For now, I just use a local copy that I've fixed
    conn = http.client.HTTPConnection("localhost:8000")

    conn.request("GET", "/devices/tech/dalvik/instruction-formats.html")
    fparser = TableParser("format")
    fparser.feed(conn.getresponse().read().decode())
    formats = dict()
    for row in fparser.table:
        formatid = row[1]
        try:
            num_regs = int(formatid[1])
            typecode = formatid[2]
        except ValueError:
            num_regs = -1
            typecode = formatid[1:]
        formats[formatid] = SmaliInstructionFormat(
            _formatid=formatid,
            format_=row[0],
            syntax=row[2],
            insn_len=int(formatid[0]),
            num_regs=num_regs,
            typecode=typecode,
        )

    conn.request("GET", "/devices/tech/dalvik/dalvik-bytecode.html")
    iparser = TableParser("instruc")
    iparser.feed(conn.getresponse().read().decode())
    insns = dict()
    for row in iparser.table:
        if ".." in row[0]:
            for opcode in range(int(row[0][:2], 16), int(row[0][4:6], 16) + 1):
                insns[opcode] = parse_row(row, formats, opcode)
        else:
            insn = parse_row(row, formats)
            insns[insn._opcode] = insn

    with open(INSTRUCTIONS_PICKLE_PATH, "bw") as f:
        dump(insns, f)


if __name__ == "__main__":
    gen_instruction_info()
