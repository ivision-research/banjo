# Banjo

![logo](doc/banjo_small.png)

_Android Dex disassembler and Binary Ninja plugin_

## Description

Banjo parses Dex files and disassembles them into a smali syntax that is close to [baksmali](https://github.com/JesusFreke/smali)'s.

There are three parts to this project:

- Core disassembler library in [android/](android)
- Binary Ninja plugin in [architecture.py](architecture.py) and [binaryview.py](binaryview.py)
- Standalone disassembler script in [disas_to_files.py](disas_to_files.py)

For more documentation, see the [doc/](doc) directory.

There are still some rough edges. See [GitHub issues](https://github.com/CarveSystems/banjo/issues) for more details.

This project was released at a [ShmooCon 2020 talk](https://github.com/CarveSystems/presentations/tree/master/2020/banjo).

## Installation Instructions

Make sure Binary Ninja is using Python 3.8.

`cd ~/.binaryninja/plugins/ && git clone https://github.com/carvesystems/banjo.git`
