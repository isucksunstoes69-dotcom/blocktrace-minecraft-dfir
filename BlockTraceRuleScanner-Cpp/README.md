# BlockTrace Rule Scanner — Native C++ build

Run `BlockTraceRuleScanner.exe`. This is a native C++ Win32 executable with no .NET runtime requirement.

The desktop interface uses a Javaw-inspired dark signature-console layout: target queue chips, rule-source controls, scan status cards, signature input, and findings output.

Load `.txt`, `.md`, `.json`, `.yml`, `.yaml`, `.yar`, or `.yara` rule text, then run the signature queue. The bundled default source is `rules\minecraft-dfir-rules.md`.
