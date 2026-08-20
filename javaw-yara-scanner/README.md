# BlockTrace Rule Scanner — Javaw GUI edition

This project adapts the Javaw `src/gui` presentation architecture (ImGui, GLFW, OpenGL, starfield, and theme) into a path-based YARA/text-rule coverage scanner.

## Build
```powershell
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=C:\path\to\vcpkg\scripts\buildsystems\vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows
cmake --build build --config Release
```

## Run
Start `build\Release\BlockTraceRuleScanner.exe`, choose a readable `.txt`, `.md`, `.json`, `.yml`, or `.yaml` file, then select **START RULE SCAN**. The scanner counts YARA rule/string declarations and checks the requested indicator terms. It does not inspect process memory.
