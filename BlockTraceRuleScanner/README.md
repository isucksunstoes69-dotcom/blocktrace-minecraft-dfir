# BlockTrace Rule Scanner (Windows EXE)

Run `BlockTraceRuleScanner.exe` on Windows with the .NET 10 Desktop Runtime installed.

The scanner opens a Javaw-inspired signature-console UI. It loads readable YARA text files (`.txt`, `.md`, `.json`, `.yml`, `.yaml`, `.yar`, `.yara`), parses rule declarations and string identifiers, and checks the enabled targets:

`dnscache`, `lsass.exe`, `javaw.exe`, `dcom`, `SysMain`, `PcaSvc`, `Bam`, `Schedule`, `EventLog`, `DusmSvc`, `DPS`, `CDPSvc`.

The bundled default rule source is `rules\minecraft-dfir-rules.md` next to the executable.
