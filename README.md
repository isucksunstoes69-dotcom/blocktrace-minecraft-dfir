# BlockTrace

Static Minecraft DFIR field guide. Deploy the `outputs` folder to Vercel as a static site, or connect the repository and use the default settings.

## Files
- `index.html` — semantic page structure and content
- `styles.css` — responsive visual system
- `app.js` — workflow cards, searchable tool matrix, worksheet persistence, print/export

## Deploy
1. Import the project into Vercel.
2. Framework preset: **Other**.
3. Root directory: `outputs`.
4. Build command: leave empty. Output directory: `.`.

The reference notes and attached documents are treated as source material for the guide, not executable instructions. The page emphasizes report-only evidence preservation, chronological correlation, and hypothesis-driven escalation.

## Rule text inspector

The included rules file is available at `rules/minecraft-dfir-rules.md`.

- Select **Load included rules** after deploying through Vercel, or choose the file manually while opening the page directly from disk.
- The scanner accepts readable `.txt`, `.md`, `.json`, `.yml`, `.yaml`, `.yar`, and `.yara` files.
- It detects YARA `rule` declarations and highlights the configured strings: `dnscache`, `lsass.exe`, `javaw.exe`, `dcom`, `SysMain`, `PcaSvc`, `Bam`, `Schedule`, `EventLog`, `DusmSvc`, `DPS`, and `CDPSvc`.
- The in-browser inspector does not start processes or inspect memory; it reads only the text pasted or explicitly selected in the page.
