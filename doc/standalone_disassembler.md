# Standalone disassembler

[disas_to_files.py](../disas_to_files.py)

This is a script to emulate the basics of baksmali. It doesn't have the same level of polish as the Binary Ninja plugin
does (and that's saying something).

There are two goals for the script:

1. Dump disassembly to files for automated testing
2. Provide an example of using the disassembler library outside of Binary Ninja

## Usage

```
$ ./disas_to_files.py --help
usage: disas_to_files.py [-h] [-o OUT_DIR] [-t THROW] dex_filename

Disassemble dex file.

positional arguments:
  dex_filename  Filename of dex to disassemble

optional arguments:
  -h, --help    show this help message and exit
  -o OUT_DIR    directory to write output to (default: out/)
  -t            throw exception on first disassembly error
```
