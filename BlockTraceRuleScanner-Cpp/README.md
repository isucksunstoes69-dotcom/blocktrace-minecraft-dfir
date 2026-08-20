# BlockTrace Rule Scanner — Native C++ build

Run `BlockTraceRuleScanner.exe`. This native C++ Win32 executable does not require the .NET runtime.

## Provide the rule path
1. Enter the absolute path to a readable YARA rule-text file in **RULE PATH**.
2. Click **LOAD PATH**.
3. Click **RUN SIGNATURE QUEUE**.

The file may use `.txt`, `.md`, `.json`, `.yml`, `.yaml`, `.yar`, or `.yara`. You can also use **BROWSE RULE TEXT** to select it.

This release fixes the GUI paint loop and shows the full Javaw-inspired signature-console interface: source controls, selectable target queue, input editor, scan status, counts, and findings.
