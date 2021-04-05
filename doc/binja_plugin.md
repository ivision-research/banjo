# Binary Ninja plugin

The binja plugin has a number of quirks. The main reasons for this are:

- Disassembling high level VMs like Dalvik is not the primary use-case of Binary Ninja.
- It seems like the BinaryView and Architecture APIs are less polished than Function analysis APIs.
- This is the first Binary Ninja plugin the author has written.

## Settings

Binary Ninja's settings have a large impact on the UX of this plugin.

Ensure that `python.interpreter` is set to Python3.8 or higher, e.g. `/usr/lib/libpython3.8.so.1.0`.

If the setting `analysis.mode` is `controlFlow` or `basic`, loading Dex files works as expected. If it is `intermediate` or `full`, then the default view mode is hex, and nothing disassembles until the mode is switched to linear or graph disassembly.

None of Binary Ninja's analysis is useful for Dex files. The following settings significantly increase the loading speed:

```json
	"analysis" :
	{
		"limits.maxFunctionSize" : 0,
		"linearSweep.autorun" : false,
		"mode" : "controlFlow",
		"neverSaveUndoData" : true,
		"suppressNewAutoFunctionAnalysis" : true,
		"tailCallHeuristics" : false,
		"tailCallTranslation" : false
	},
```
