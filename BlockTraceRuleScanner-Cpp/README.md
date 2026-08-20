# BlockTrace Rule Scanner — Native C++ build

Run `BlockTraceRuleScanner.exe`. This native C++ Win32 executable does not require the .NET runtime.

## Provide the rule path
1. Enter the absolute path to a readable YARA rule-text file in **RULE PATH**.
2. Click **LOAD PATH**.
3. Click **RUN SIGNATURE QUEUE**.

The file may use `.txt`, `.md`, `.json`, `.yml`, `.yaml`, `.yar`, or `.yara`. You can also use **BROWSE RULE TEXT** to select it.

The Javaw-inspired signature-console layout contains target queue chips, rule-source controls, scan state, input editor, and findings output. The bundled default source path appears automatically in the path box: `rules\minecraft-dfir-rules.md` beside the EXE.
