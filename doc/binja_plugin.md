# Binary Ninja plugin

The binja plugin has a number of quirks. The main reasons for this are:

- Disassembling high level VMs like Dalvik in Binary Ninja is not its primary use-case.
- It seems like the BinaryView and Architecture APIs are less polished than Function analysis Apis.
- This is the first Binary Ninja plugin the author has written.

## Behavior to be aware of

You can't use multiple tabs in the same Binary Ninja window. See https://github.com/CarveSystems/banjo/issues/14.

The plugin writes to `/tmp/out.json` and `/tmp/out.json.pickle`. See https://github.com/CarveSystems/banjo/issues/8.

An attacker who can write to `/tmp/out.json.pickle` after the plugin writes to it but before it loads from it can perform a deserialization attack and gain code execution. See https://github.com/CarveSystems/banjo/issues/10.

Control flow is wrong for most switches. See https://github.com/CarveSystems/banjo/issues/15.

## Settings

Binary Ninja's settings have a large impact on the UX of this plugin.

Ensure that `python.interpreter` is set to Python3.8, e.g. `/usr/lib/libpython3.8.so.1.0`.

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
