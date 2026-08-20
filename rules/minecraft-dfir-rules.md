rule VapeV4_Launcher
{
    strings:
        $name1      = "Vape V4 Launcher" ascii
        $name2      = "Vape V4 Loader" ascii
        $ua         = "User-Agent: Vape4/Launcher" ascii
        $domain1    = "online.vape.gg" ascii
        $domain2    = "www.vape.gg" ascii
        $api        = "/api/v1/app-auth/generate" ascii
        $authflow   = "vape.gg/app-auth/proceed/" ascii
        $edition    = "edition=v4" ascii
        $dir        = ".vapeclient" ascii
        $rich       = { 52 69 63 68 3E AD 76 C3 }

    condition:
        uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550
        and filesize < 15MB
        and (
            ($rich and $name1 and $ua)
            or
            ($name1 and $ua and $api and $domain1 and $edition)
            or
            ($name2 and $authflow and $domain2)
        )
}

rule VoilLoader_Cheat_JAR
{
    strings:
        $pkg        = "lol/lwes/voilloader/VoilLoader" ascii
        $mod_id     = "voilloader" ascii
        $native_pkg = "lol/lwes/voil/Native" ascii
        $build_cls  = "a/bdf08be35c68e969d/a" ascii
        $build_id   = "df08be35c68e969d" ascii
        $login      = "lambda$doLogin$0" ascii
        $auth_err   = "lambda$handleAuthError$5" ascii
        $mc_ver     = "lambda$getMcVersion$0" ascii
        $token1     = "UR7321" ascii
        $token2     = "McF2$6" ascii
        $hash1      = "14e10f6ef737f95" ascii
        $hash2      = "210f68308304c56" ascii

    condition:
        uint32(0) == 0x04034b50
        and filesize < 5MB
        and (
            ($pkg and $mod_id and $native_pkg and $login)
            or
            ($build_cls and $auth_err)
            or
            ($token1 and $token2 and $hash1 and $hash2 and $pkg)
        )
}

rule PrestigeInjector
{
    strings:
        $url        = "https://api.prestigeclient.vip" ascii
        $resolve1   = "api.prestigeclient.vip:443:172.67.137.182" ascii
        $resolve2   = "api.prestigeclient.vip:80:172.67.137.182" ascii
        $endpoint   = "/injectorNewDownload" ascii
        $dll_log    = "DLL downloaded, size: " ascii
        $jni_err    = "JNI_OnLoad not found in DLL" ascii
        $rich       = { 52 69 63 68 6C 71 F1 AB }

    condition:
        uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550
        and filesize < 2MB
        and (
            ($rich and $url and $endpoint and $dll_log and $jni_err)
            or
            ($url and $endpoint and $dll_log and ($resolve1 or $resolve2))
        )
}

import "pe"
import "dotnet"
import "math"

private rule _clicker_user32_any {
  condition:
    pe.is_pe and
    pe.imports(
      /user32\.dll/i,
      /(GetAsyncKeyState|GetKeyState|SendInput|mouse_event|keybd_event|SetCursorPos|GetCursorPos|SetWindowsHookExA|SetWindowsHookExW|CallNextHookEx|PostMessageW)/
    ) > 0
}

private rule _clicker_key_state {
  condition:
    pe.is_pe and
    pe.imports(/user32\.dll/i, /(GetAsyncKeyState|GetKeyState)/) > 0
}

private rule _clicker_active_input {
  condition:
    pe.is_pe and
    pe.imports(/user32\.dll/i, /(SendInput|mouse_event|keybd_event|SetCursorPos|SetWindowsHookExA|SetWindowsHookExW|CallNextHookEx|PostMessageW|SendMessageW)/) > 0
}

rule CLICKER_DOTNET_GENERIC_PE : clicker cheat dotnet generic {
  meta:
    author = "Jumarf"
    description = "Generalized .NET clicker detector using hotkey APIs, clicker naming, and UI hints"
    scope = "Generic PE payloads"

  strings:
    $api1 = "GetAsyncKeyState" ascii wide
    $api2 = "GetKeyState" ascii wide
    $api3 = "SendInput" ascii wide
    $api4 = "mouse_event" ascii wide
    $api5 = "SetCursorPos" ascii wide
    $name1 = /[-a-z0-9_ .+]{0,24}clicker(\.dll|\.exe)?/i ascii wide
    $kw1 = "autoclicker" ascii wide nocase
    $kw2 = "click interval" ascii wide nocase
    $kw3 = "jitter" ascii wide nocase fullword
    $kw4 = "butterfly" ascii wide nocase fullword
    $kw5 = "double clicker" ascii wide nocase
    $kw6 = "click sounds" ascii wide nocase
    $kw7 = "left clicker" ascii wide nocase
    $kw8 = "right clicker" ascii wide nocase
    $kw9 = "left cps" ascii wide nocase
    $kw10 = "right cps" ascii wide nocase
    $kw11 = "click recorder" ascii wide nocase
    $kw12 = "click player" ascii wide nocase
    $ui1 = "Guna.UI2" ascii wide
    $ui2 = "Siticone.Desktop.UI" ascii wide
    $ui3 = "Bunifu" ascii wide
    $ui4 = "MaterialSkin" ascii wide
    $ui5 = "MetroSet" ascii wide

  condition:
    pe.is_pe and
    dotnet.is_dotnet and
    filesize <= 67108864 and
    1 of ($api*) and
    (
      $name1 or
      2 of ($kw*)
    ) and
    (
      $name1 or
      1 of ($ui*) or
      1 of ($kw1, $kw2, $kw3, $kw4, $kw5, $kw6, $kw7, $kw8, $kw9, $kw10) or
      for any ref in dotnet.assembly_refs : (
        ref.name icontains "Guna" or
        ref.name icontains "Siticone" or
        ref.name icontains "Bunifu" or
        ref.name icontains "MaterialSkin" or
        ref.name icontains "MetroSet"
      )
    )
}

rule CLICKER_DOTNET_MINECRAFT_PE : clicker cheat dotnet minecraft {
  meta:
    author = "Jumarf"
    description = "Generalized .NET Minecraft clicker UI detector"
    scope = "Minecraft-oriented PE payloads"

  strings:
    $clk1 = "clicker" ascii wide nocase fullword
    $clk2 = "autoclicker" ascii wide nocase fullword
    $clk3 = "auto clicker" ascii wide nocase
    $clk4 = "left clicker" ascii wide nocase
    $clk5 = "right clicker" ascii wide nocase
    $clk6 = "left cps" ascii wide nocase
    $clk7 = "right cps" ascii wide nocase
    $clk8 = "min cps" ascii wide nocase
    $clk9 = "max cps" ascii wide nocase
    $clk10 = "clicks per second" ascii wide nocase
    $clk11 = "jitter" ascii wide nocase fullword
    $clk12 = "butterfly" ascii wide nocase fullword
    $clk13 = "double click" ascii wide nocase
    $clk14 = "blockhit" ascii wide nocase fullword
    $ctx1 = "minecraft" ascii wide nocase fullword
    $ctx2 = "hypixel" ascii wide nocase fullword
    $ctx3 = "lunar client" ascii wide nocase
    $ctx4 = "badlion" ascii wide nocase fullword
    $ctx5 = "feather client" ascii wide nocase
    $ctx6 = "pvplounge" ascii wide nocase fullword
    $ctx7 = "javaw.exe" ascii wide nocase
    $ctx8 = ".minecraft" ascii wide nocase

  condition:
    pe.is_pe and
    dotnet.is_dotnet and
    1 of ($clk1, $clk2, $clk3, $clk4, $clk5) and
    1 of ($clk6, $clk7, $clk8, $clk9, $clk10, $clk11, $clk12, $clk13, $clk14) and
    (
      1 of ($ctx*) or
      for any s in dotnet.user_strings : (
        s icontains "minecraft" or
        s icontains "hypixel" or
        s icontains "lunar client" or
        s icontains ".minecraft" or
        s icontains "javaw.exe"
      )
    )
}

rule CLICKER_NATIVE_GENERIC_PE : clicker cheat native generic {
  meta:
    author = "Jumarf"
    description = "Generalized native clicker detector using key-state APIs and clicker-oriented naming"
    scope = "Native PE payloads"

  strings:
    $name1 = /[-a-z0-9_ .+]{0,24}clicker(\.dll|\.exe)?/i ascii wide
    $kw1 = /\bauto\s*click(er)?\b/i ascii wide
    $kw2 = /\bclick\s*interval\b/i ascii wide
    $kw3 = /\bjitter\b/i ascii wide
    $kw4 = /\bbutterfly\b/i ascii wide
    $kw5 = /\bdouble[-_\s]*clicker\b/i ascii wide
    $kw6 = /\bleft\s*click(er)?\b/i ascii wide
    $kw7 = /\bright\s*click(er)?\b/i ascii wide
    $kw8 = /\bleft\s*cps\b/i ascii wide
    $kw9 = /\bright\s*cps\b/i ascii wide
    $kw10 = /\bclick\s*sounds?\b/i ascii wide

  condition:
    pe.is_pe and
    not dotnet.is_dotnet and
    filesize <= 67108864 and
    pe.number_of_imported_functions <= 220 and
    _clicker_key_state and
    (
      _clicker_active_input or
      pe.imports(/kernel32\.dll/i, /(OpenProcess|ReadProcessMemory|WriteProcessMemory)/) > 0
    ) and
    (
      $name1 or
      1 of ($kw*)
    )
}

rule CLICKER_CONSOLE_CPS_PROMPT_PE : clicker cheat native console {
  meta:
    author = "Jumarf"
    description = "Console clickers that prompt for left and right CPS values"
    scope = "Native PE payloads"

  strings:
    $p1 = "How much CPS do you want" ascii wide nocase
    $p2 = "Left Clicker ->" ascii wide nocase
    $p3 = "Right Clicker ->" ascii wide nocase
    $p4 = "Left Clicker" ascii wide nocase
    $p5 = "Right Clicker" ascii wide nocase

  condition:
    pe.is_pe and
    not dotnet.is_dotnet and
    pe.imports(/user32\.dll/i, /GetAsyncKeyState/) > 0 and
    3 of them
}

rule CLICKER_NATIVE_MINECRAFT_CONSOLE_PE : clicker cheat native minecraft {
  meta:
    author = "Jumarf"
    description = "Console-style native Minecraft clickers that wait for Java/Minecraft and tune CPS"
    scope = "Native PE payloads"

  strings:
    $a1 = "Autoclicker->" ascii wide nocase
    $a2 = "Set autoclicker toggle key" ascii wide nocase
    $a3 = "CPS min ->" ascii wide nocase
    $a4 = "CPS max ->" ascii wide nocase
    $a5 = "Min Cps" ascii wide nocase
    $a6 = "Max Cps" ascii wide nocase
    $ctx1 = "Minecraft process found." ascii wide nocase
    $ctx2 = "Waiting for minecraft process..." ascii wide nocase
    $ctx3 = "javaw.exe" ascii wide nocase
    $api1 = "OpenProcess" ascii wide
    $api2 = "ReadProcessMemory" ascii wide
    $api3 = "WriteProcessMemory" ascii wide
    $api4 = "GetAsyncKeyState" ascii wide
    $api5 = "GetKeyState" ascii wide

  condition:
    pe.is_pe and
    not dotnet.is_dotnet and
    3 of ($a*) and
    1 of ($ctx*) and
    4 of ($api*)
}

rule CLICKER_OPENGL_MINECRAFT_PANEL_PE : clicker cheat panel minecraft {
  meta:
    author = "Jumarf"
    description = "OpenGL and raw-input based Minecraft clicker panels with in-game tuning options"
    scope = "Native PE payloads"

  strings:
    $a1 = "Hold R-Click" ascii wide nocase
    $a2 = "Only Minecraft" ascii wide nocase
    $a3 = "Jitter" ascii wide nocase
    $a4 = "Jitter Simulation" ascii wide nocase
    $a5 = "Min Cps" ascii wide nocase
    $a6 = "Max Cps" ascii wide nocase
    $a7 = "Lunar Clicker" ascii wide nocase
    $a8 = "Minecraft" ascii wide nocase

  condition:
    pe.is_pe and
    not dotnet.is_dotnet and
    pe.imports(/opengl32\.dll/i, /gl/i) > 0 and
    4 of them
}

rule CLICKER_RECORDER_REPLAYER : clicker recorder replay {
  meta:
    author = "Jumarf"
    description = "Click recorder and click playback utilities used as clicker tooling"
    scope = "PE payloads"

  strings:
    $rec1 = "click recorder" ascii wide nocase
    $rec2 = "click player" ascii wide nocase
    $rec3 = "record clicks" ascii wide nocase
    $rec4 = "recorded clicks" ascii wide nocase
    $rec5 = "playback" ascii wide nocase fullword
    $rec6 = "replay clicks" ascii wide nocase
    $rec7 = "mouse recorder" ascii wide nocase
    $rec8 = "repeat clicks" ascii wide nocase
    $rec9 = "macro recorder" ascii wide nocase
    $api1 = "GetAsyncKeyState" ascii wide
    $api2 = "SendInput" ascii wide
    $api3 = "mouse_event" ascii wide
    $api4 = "SetCursorPos" ascii wide
    $api5 = "GetCursorPos" ascii wide

  condition:
    pe.is_pe and
    (
      (
        2 of ($rec1, $rec2, $rec3, $rec4, $rec6, $rec7, $rec9) and
        1 of ($rec5, $rec8)
      ) or
      4 of ($rec*)
    ) and
    (
      _clicker_user32_any or
      2 of ($api*)
    )
}

rule CLICKER_TEXT_ARTIFACT : clicker artifact text minecraft {
  meta:
    author = "Jumarf"
    description = "Readmes, configs, and text artifacts that describe clickers or Minecraft CPS tuning"
    scope = "Non-PE text and mixed artifacts"

  strings:
    $clk1 = "clicker" ascii nocase fullword
    $clk2 = "autoclicker" ascii nocase fullword
    $clk3 = "auto clicker" ascii nocase
    $clk4 = "left cps" ascii nocase
    $clk5 = "right cps" ascii nocase
    $clk6 = "min cps" ascii nocase
    $clk7 = "max cps" ascii nocase
    $clk8 = "clicks per second" ascii nocase
    $clk9 = "jitter" ascii nocase fullword
    $clk10 = "butterfly" ascii nocase fullword
    $clk11 = "click recorder" ascii nocase
    $clk12 = "click player" ascii nocase
    $ctx1 = "minecraft" ascii nocase fullword
    $ctx2 = "hypixel" ascii nocase fullword
    $ctx3 = "lunar client" ascii nocase
    $ctx4 = "javaw.exe" ascii nocase
    $ctx5 = ".minecraft" ascii nocase
    $ctx6 = "hwid" ascii nocase fullword

  condition:
    not pe.is_pe and
    3 of ($clk*) and
    1 of ($ctx*)
}

private rule _generic_input_apis {
  condition:
    pe.is_pe and
    pe.imports(/user32\.dll/i, /(GetAsyncKeyState|SendInput|mouse_event|keybd_event|SetWindowsHookExA|SetWindowsHookExW|CallNextHookEx|GetCursorPos|SetCursorPos)/) > 0
}

rule Generic_DotNet_Clicker_UI : cheat clicker generic dotnet {
  meta:
    author = "Jumarf"
    description = "Generic high-confidence .NET clicker detector using UI and Minecraft-oriented strings"

  strings:
    $clicker = "clicker" ascii wide nocase
    $autoclicker = "autoclicker" ascii wide nocase
    $left = "left clicker" ascii wide nocase
    $right = "right clicker" ascii wide nocase
    $jitter = "jitter" ascii wide nocase
    $reach = "reach" ascii wide nocase
    $velocity = "velocity" ascii wide nocase
    $minecraft = "minecraft" ascii wide nocase
    $hypixel = "hypixel" ascii wide nocase
    $hwid = "hwid" ascii wide nocase
    $lunar = "lunar client" ascii wide nocase
    $javaw = "javaw.exe" ascii wide nocase

  condition:
    pe.is_pe and
    dotnet.is_dotnet and
    not (
      dotnet.assembly.name == "Siticone.Desktop.UI" or
      dotnet.assembly.name == "Guna.UI2" or
      dotnet.assembly.name == "Microsoft.Toolkit.Uwp.Notifications" or
      dotnet.assembly.name == "Microsoft.Windows.SDK.NET" or
      dotnet.assembly.name == "System.ValueTuple" or
      dotnet.assembly.name == "WinRT.Runtime"
    ) and
    $clicker and
    2 of ($autoclicker, $left, $right, $jitter, $reach, $velocity) and
    1 of ($minecraft, $hypixel, $hwid, $lunar, $javaw)
}

rule Generic_Native_Clicker_Module : cheat clicker generic native {
  meta:
    author = "Jumarf"
    description = "Generic native clicker detector for Minecraft-oriented input modules"

  strings:
    $clicker = "clicker" ascii wide nocase
    $autoclick = "autoclick" ascii wide nocase
    $jitter = "jitter" ascii wide nocase
    $reach = "reach" ascii wide nocase
    $velocity = "velocity" ascii wide nocase
    $aim = "aim assist" ascii wide nocase
    $minecraft = "minecraft" ascii wide nocase
    $lunar = "lunar client" ascii wide nocase
    $hypixel = "hypixel" ascii wide nocase

  condition:
    pe.is_pe and
    not dotnet.is_dotnet and
    _generic_input_apis and
    2 of ($clicker, $autoclick, $jitter, $reach, $velocity, $aim) and
    1 of ($minecraft, $lunar, $hypixel)
}

rule CLICKER_NATIVE_LOW_IMPORT_PROFILE_PE : clicker cheat native sparseimports {
  meta:
    author = "Jumarf"
    description = "Native clickers with user32-driven automation and a deliberately small import surface"
    scope = "Native PE payloads"

  strings:
    $kw1 = "clicker" ascii wide nocase
    $kw2 = "autoclick" ascii wide nocase
    $kw3 = "left cps" ascii wide nocase
    $kw4 = "right cps" ascii wide nocase
    $kw5 = "jitter" ascii wide nocase
    $kw6 = "butterfly" ascii wide nocase
    $ctx1 = "only minecraft" ascii wide nocase
    $ctx2 = "javaw.exe" ascii wide nocase
    $ctx3 = "lunar client" ascii wide nocase
    $ctx4 = "hypixel" ascii wide nocase

  condition:
    pe.is_pe and
    not dotnet.is_dotnet and
    pe.number_of_imported_functions <= 90 and
    pe.imports(
      /user32\.dll/i,
      /(GetAsyncKeyState|GetKeyState|SendInput|mouse_event|keybd_event|GetCursorPos|SetCursorPos|SetWindowsHookExA|SetWindowsHookExW|CallNextHookEx)/
    ) > 0 and
    pe.imports(/winhttp\.dll/i, /./) == 0 and
    pe.imports(/wininet\.dll/i, /./) == 0 and
    pe.imports(/crypt32\.dll/i, /./) == 0 and
    pe.imports(/bcrypt\.dll/i, /./) == 0 and
    pe.imports(/secur32\.dll/i, /./) == 0 and
    2 of ($kw*) and
    1 of ($ctx*)
}

private rule _pack02_native_clicker_cluster {
  meta:
    author = "Jumarf"
    block = "pack2"
    role = "native_minecraft_clicker"

  strings:
    $clicker = "clicker" ascii wide nocase
    $autoclicker = "autoclicker" ascii wide nocase
    $autoclicker2 = "auto clicker" ascii wide nocase
    $left = "left clicker" ascii wide nocase
    $right = "right clicker" ascii wide nocase
    $double = "double clicks" ascii wide nocase
    $require = "require click" ascii wide nocase
    $jitter = "jitter" ascii wide nocase
    $reach = "reach" ascii wide nocase
    $velocity = "velocity" ascii wide nocase
    $aim = "aim assist" ascii wide nocase
    $cps1 = "Clicks per second" ascii wide nocase
    $cps2 = "Enter new CPS" ascii wide nocase
    $cps3 = "Min Cps" ascii wide nocase
    $cps4 = "Max Cps" ascii wide nocase
    $cps5 = "Set CPS" ascii wide nocase
    $random = "clicker randomization" ascii wide nocase
    $mc1 = "\\.minecraft\\options.txt" ascii wide nocase
    $mc2 = "Waiting for minecraft process..." ascii wide nocase
    $mc3 = "Minecraft process found." ascii wide nocase
    $mc4 = "No supported Minecraft version" ascii wide nocase
    $lunar = "Lunar Client" ascii wide nocase
    $javaw = "javaw.exe" ascii wide nocase
    $hwid = "HWID" ascii wide nocase
    $ozix1 = "Ozix Autoclicker v5.0" ascii wide nocase
    $ozix2 = "Account Ozix" ascii wide nocase
    $wevtutil = "wevtutil.exe el" ascii wide nocase
    $detect = "anticheat detections" ascii wide nocase

  condition:
    pe.is_pe and
    pe.imports(/user32\.dll/i, /(GetAsyncKeyState|keybd_event|SendInput|SetWindowsHookExA|CallNextHookEx|SetCursorPos)/) > 0 and
    5 of ($clicker, $autoclicker, $autoclicker2, $left, $right, $double, $require, $jitter, $reach, $velocity, $aim, $cps1, $cps2, $cps3, $cps4, $cps5, $random, $hwid, $ozix1, $ozix2, $detect) and
    1 of ($mc1, $mc2, $mc3, $mc4, $lunar, $javaw, $wevtutil, $ozix1)
}

private rule _pack02_prefetch_trace_cleanup_dll {
  meta:
    author = "Jumarf"
    block = "pack2"
    role = "prefetch_trace_cleanup_helper"

  strings:
    $pdb = "MoonDLL.pdb" ascii nocase
    $prefetch = "Prefetch" ascii nocase
    $processhac = "PROCESSHAC*.pf" ascii nocase
    $visited = "VisitedPidlMRU" ascii nocase
    $recent = "RecentDocs" ascii nocase
    $feature = "FeatureUsage" ascii nocase
    $comdlg = "ComDlg32" ascii nocase
    $appcompat = "AppCompatFlags" ascii nocase
    $open = "OpenProcess" ascii nocase
    $proc1 = "Process32FirstW" ascii nocase
    $proc2 = "Process32NextW" ascii nocase

  condition:
    pe.is_pe and
    $pdb and
    6 of them
}

rule Pack02_NativeMinecraftClicker_Cluster : pack02 cheat clicker minecraft native {
  meta:
    author = "Jumarf"
    description = "Pack02 cluster: native Minecraft clickers, disguised installer clicker, and trace-cleaning helper DLL"
    scope = "Covers the concrete pack2 cluster with low overlap on unrelated PE files"

  condition:
    _pack02_native_clicker_cluster or
    _pack02_prefetch_trace_cleanup_dll
}

private rule _pack15_swift_clicker {
  meta:
    author = "Jumarf"
    block = "pack15"
    role = "swift_dotnet_clicker"

  strings:
    $a = "Swift.Mods" ascii wide nocase
    $b = "Swift.Clicker.resources" ascii wide nocase
    $c = "Clicker_Load" ascii wide nocase
    $d = "Clicker.exe" ascii wide nocase

  condition:
    pe.is_pe and
    dotnet.is_dotnet and
    all of them
}

private rule _pack15_thunder_clicker {
  meta:
    author = "Jumarf"
    block = "pack15"
    role = "thunder_hypixel_clicker"

  strings:
    $a = "Thunder Clicker Hypixel Test Closed Beta" ascii wide nocase
    $b = "thunderclicker" ascii wide nocase
    $b2 = "Thunder_Clicker_Hypixel_Test_Closed_Beta" ascii wide nocase
    $b3 = "ThunderClicker4.0" ascii wide nocase
    $b4 = "ThunderClicker5.0" ascii wide nocase
    $c = "Autoclicker_Tick" ascii wide nocase
    $d = "LClickerCheckBox_CheckedChanged_1" ascii wide nocase
    $e = "siticoneHtmlLabel" ascii wide nocase

  condition:
    pe.is_pe and
    dotnet.is_dotnet and
    3 of ($a, $b, $b2, $b3, $b4, $c, $d, $e)
}

private rule _pack15_toad_clicker {
  meta:
    author = "Jumarf"
    block = "pack15"
    role = "toad_clicker_family"

  strings:
    $a = "Toad.exe" ascii nocase
    $b = ".toad" ascii nocase
    $c = "dclicker_enabled" ascii nocase
    $d = "dclicker_delay" ascii nocase

  condition:
    pe.is_pe and
    all of them
}

private rule _pack15_sstool_protected {
  meta:
    author = "Jumarf"
    block = "pack15"
    role = "sstool_vmp_clicker"

  strings:
    $a = "Siticone.UI.WinForms" ascii wide nocase
    $b = "SiticoneButton" ascii wide nocase

  condition:
    pe.is_pe and
    dotnet.is_dotnet and
    $a and $b and
    for any section in pe.sections : (
      section.name == ".vmp1" and
      section.raw_data_size >= 0x100000 and
      math.entropy(section.raw_data_offset, section.raw_data_size) >= 7.90
    )
}

rule Pack15_ThunderSwiftCluster : pack15 cheat clicker thunder swift {
  meta:
    author = "Jumarf"
    description = "Pack15 cluster for Swift, Thunder, Toad, and SSTool clicker families"
    scope = "Content-only detection for the concrete pack15 families while excluding bare Siticone libraries"

  condition:
    any of (
      _pack15_swift_clicker,
      _pack15_thunder_clicker,
      _pack15_toad_clicker,
      _pack15_sstool_protected
    )
}

private rule _pack16_sapphire_lite {
  meta:
    author = "Jumarf"
    block = "pack16"
    role = "sapphire_lite_clicker"

  strings:
    $a = "Sapphire LITE" ascii wide nocase
    $b = "Sapphire_LITE" ascii wide nocase
    $c = "minecraft_process" ascii wide nocase
    $d = "leftClickerBindButton" ascii wide nocase
    $e = "rightClickerBindButton" ascii wide nocase

  condition:
    pe.is_pe and
    dotnet.is_dotnet and
    4 of them
}

private rule _pack16_scatter_clicker {
  meta:
    author = "Jumarf"
    block = "pack16"
    role = "scatter_imgui_clicker"

  strings:
    $a = "Scatter" ascii nocase
    $b = "AutoClicker" ascii nocase
    $c = "GetAsyncKeyState" ascii nocase
    $d = "mouse_event" ascii nocase
    $e = "example_win32_directx11.pdb" ascii nocase

  condition:
    pe.is_pe and
    4 of them
}

private rule _pack16_slinky_loader {
  meta:
    author = "Jumarf"
    block = "pack16"
    role = "slinky_clicker_loader"

  strings:
    $a = "slinky.dat" ascii nocase
    $b = "Starting clicker..." ascii nocase
    $c = "Failed to initialize clicker engine." ascii nocase

  condition:
    pe.is_pe and
    all of them and
    for any section in pe.sections : (
      section.name == ".vlizer" and
      math.entropy(section.raw_data_offset, section.raw_data_size) >= 7.95
    )
}

rule Pack16_SapphireSlinkyCluster : pack16 cheat clicker sapphire slinky {
  meta:
    author = "Jumarf"
    description = "Pack16 cluster for Sapphire LITE, Scatter, and Slinky clicker loaders"
    scope = "Content-only detection for the concrete pack16 families"

  condition:
    any of (
      _pack16_sapphire_lite,
      _pack16_scatter_clicker,
      _pack16_slinky_loader
    )
}

private rule _pack17_mango_lite {
  meta:
    author = "Jumarf"
    block = "pack17"
    role = "mango_lite_clicker"

  strings:
    $a = "Autoclicker_Tick" ascii wide nocase
    $b = "lite.Form1+<Autoclicker_Tick>d__14" ascii wide nocase

  condition:
    pe.is_pe and
    dotnet.is_dotnet and
    dotnet.assembly.name == "lite" and
    all of them
}

private rule _pack17_no_bypass_clicker {
  meta:
    author = "Jumarf"
    block = "pack17"
    role = "nobypass_dotnet_clicker"

  strings:
    $a = "NoBypass.Commands.API" ascii wide nocase
    $b = "No Bypass Clicker" ascii wide nocase

  condition:
    pe.is_pe and
    dotnet.is_dotnet and
    all of them
}

private rule _pack17_ozix_crack {
  meta:
    author = "Jumarf"
    block = "pack17"
    role = "ozix_crack_clicker"

  strings:
    $a = "Ozix crack -" ascii nocase
    $b = "Logging in to Ozix" ascii nocase
    $c = "Ozix Autoclicker v3.1" ascii nocase
    $d = "Minecraft 1.8.9" ascii nocase

  condition:
    pe.is_pe and
    3 of them and
    pe.imports(/user32\.dll/i, /(GetAsyncKeyState|GetCursorPos|mouse_event)/) > 0
}

rule Pack17_MangoOzixCluster : pack17 cheat clicker ozix bypass {
  meta:
    author = "Jumarf"
    description = "Pack17 cluster for Mango Lite, No Bypass, and Ozix crack clickers"
    scope = "Content-only detection for the concrete pack17 families"

  condition:
    any of (
      _pack17_mango_lite,
      _pack17_no_bypass_clicker,
      _pack17_ozix_crack
    )
}

private rule _pack18_hamzee_clicker {
  meta:
    author = "Jumarf"
    block = "pack18"
    role = "hamzee_clicker"

  strings:
    $a = "Hamzee Clicker v1.0.2" ascii wide nocase
    $b = "Hamzee" ascii wide nocase
    $c = "Only Minecraft" ascii wide nocase
    $d = "Minecraft 1.7" ascii wide nocase

  condition:
    pe.is_pe and
    3 of them
}

private rule _pack18_click_record_replay {
  meta:
    author = "Jumarf"
    block = "pack18"
    role = "record_replay_tooling"

  strings:
    $a = "ClickRecorder\\ReakClicker\\obj\\Debug\\Lightshot.pdb" ascii nocase
    $b = "ClickPlayer\\ReakClicker\\obj\\Debug\\Lightshot.pdb" ascii nocase

  condition:
    pe.is_pe and
    1 of them
}

private rule _pack18_kclicker_protected {
  meta:
    author = "Jumarf"
    block = "pack18"
    role = "kclicker_packed_family"

  condition:
    pe.is_pe and
    filesize >= 12MB and
    pe.overlay.size >= 12MB and
    math.entropy(pe.overlay.offset, pe.overlay.size) >= 7.90 and
    for any section in pe.sections : ( section.name == ".eh_fram" ) and
    pe.imports(/kernel32\.dll/i, /(GetModuleHandleA|GetProcAddress|VirtualProtect)/) > 0 and
    pe.imports(/kernel32\.dll/i, /SetUnhandledExceptionFilter/) > 0
}

rule Pack18_HamzeeKClickerCluster : pack18 cheat clicker recorder {
  meta:
    author = "Jumarf"
    description = "Pack18 cluster for Hamzee, record/replay helpers, and the packed KCLICKER family"
    scope = "Content-only detection for the concrete pack18 families"

  condition:
    any of (
      _pack18_hamzee_clicker,
      _pack18_click_record_replay,
      _pack18_kclicker_protected
    )
}

private rule _pack19_dusk_clicker {
  meta:
    author = "Jumarf"
    block = "pack19"
    role = "dusk_dotnet_clicker"

  strings:
    $a = "duskclicker" ascii wide nocase
    $b = "DuskClick.Properties.Resources.resources" ascii wide nocase
    $c = "AutoClicker_Tick" ascii wide nocase

  condition:
    pe.is_pe and
    dotnet.is_dotnet and
    (
      2 of them or
      ($a and filesize >= 5MB and for any section in pe.sections : (
        section.name == ".text" and
        section.raw_data_size >= 0x400000 and
        math.entropy(section.raw_data_offset, section.raw_data_size) >= 7.40
      ))
    )
}

private rule _pack19_empty_clicker {
  meta:
    author = "Jumarf"
    block = "pack19"
    role = "empty_clicker_family"

  strings:
    $a = "Empty Clicker" ascii nocase
    $b = "empty.wtf" ascii nocase
    $c = "empty.pdb" ascii nocase
    $d = "EmptyClicker.pdb" ascii nocase

  condition:
    pe.is_pe and
    2 of them
}

private rule _pack19_broxa_clicker {
  meta:
    author = "Jumarf"
    block = "pack19"
    role = "broxa_clicker"

  strings:
    $a = "Broxa Clicker" ascii wide nocase
    $b = "clicker_Load" ascii wide nocase

  condition:
    pe.is_pe and
    all of them
}

rule Pack19_DuskEmptyCluster : pack19 cheat clicker dusk broxa {
  meta:
    author = "Jumarf"
    description = "Pack19 cluster for Dusk, Empty.wtf, and Broxa clicker branches"
    scope = "Content-only detection for the concrete pack19 families"

  condition:
    any of (
      _pack19_dusk_clicker,
      _pack19_empty_clicker,
      _pack19_broxa_clicker
    )
}

private rule _pack20_bap_vmp_clicker {
  meta:
    author = "Jumarf"
    block = "pack20"
    role = "bap_vmp_protected_clicker"

  condition:
    pe.is_pe and
    pe.imports(/kernel32\.dll/i, /(GetModuleHandleA|GetProcAddress)/) > 0 and
    for any section in pe.sections : (
      section.name == ".vmp1" and
      section.raw_data_size >= 0x300000 and
      math.entropy(section.raw_data_offset, section.raw_data_size) >= 7.90
    )
}

private rule _pack20_bit_or_dogshit_clicker {
  meta:
    author = "Jumarf"
    block = "pack20"
    role = "named_dotnet_clicker"

  strings:
    $a = "Bit Clicker" ascii wide nocase
    $b = "Bit_Clicker.exe" ascii wide nocase
    $c = "dogshitclicker" ascii wide nocase
    $d = "get_clicker" ascii wide nocase
    $e = "LeftClicker_Tick" ascii wide nocase

  condition:
    pe.is_pe and
    dotnet.is_dotnet and
    2 of them
}

rule Pack20_BapBitCluster : pack20 cheat clicker vmp {
  meta:
    author = "Jumarf"
    description = "Pack20 cluster for BAP, Bit Clicker, and dogshitclicker builds"
    scope = "Content-only detection for the concrete pack20 families"

  condition:
    _pack20_bap_vmp_clicker or
    _pack20_bit_or_dogshit_clicker
}

private rule _pack21_aurium_clicker {
  meta:
    author = "Jumarf"
    block = "pack21"
    role = "aurium_native_clicker"

  strings:
    $a = "aurium24k#0001 v1.0" ascii nocase
    $b = "AuriumClicker.pdb" ascii nocase

  condition:
    pe.is_pe and
    all of them and
    pe.imports(/user32\.dll/i, /(GetAsyncKeyState|mouse_event)/) > 0
}

private rule _pack21_b1scoito_family {
  meta:
    author = "Jumarf"
    block = "pack21"
    role = "b1scoito_open_clicker_family"

  strings:
    $a = "https://github.com/b1scoito/clicker" ascii wide nocase
    $b = "Repository: https://github.com/b1scoito/clicker" ascii wide nocase
    $c = "##var::clicker::tabs" ascii wide nocase
    $d = "clicker randomization" ascii wide nocase
    $e = "Clicker configuration" ascii wide nocase
    $f = "Minecraft / Forge" ascii wide nocase
    $g = "##clicker_title" ascii wide nocase
    $h = "Keybindings" ascii wide nocase
    $i = "Blockhit chance %d%%" ascii wide nocase
    $j = "Lunar" ascii wide nocase
    $k = "Click to bind" ascii wide nocase
    $l = "&whiskeyH" ascii wide nocase
    $m = "imgui_impl_dx9" ascii wide nocase
    $n = "imgui_impl_win32" ascii wide nocase

  condition:
    pe.is_pe and
    (
      2 of ($a, $b, $c, $d, $e, $f) or
      3 of ($g, $h, $i, $j, $e, $f) or
      ($l and $m and $n) or
      ($k and $l and 1 of ($e, $f, $g))
    ) and
    pe.imports(/user32\.dll/i, /(GetAsyncKeyState|SetWindowsHookExA|SetWindowsHookExW|SetCursorPos|GetCursorPos)/) > 0
}

private rule _pack21_vm_boot_variant {
  meta:
    author = "Jumarf"
    block = "pack21"
    role = "vm_boot_clicker_variant"

  condition:
    pe.is_pe and
    for any section in pe.sections : (
      section.name == ".boot" and
      section.raw_data_size >= 0x80000 and
      math.entropy(section.raw_data_offset, section.raw_data_size) >= 7.90
    )
}

private rule _pack21_b1scoito_legacy_gui_variant {
  meta:
    author = "Jumarf"
    block = "pack21"
    role = "b1scoito_legacy_gui_variant"

  strings:
    $ctx1 = "clicker" ascii wide nocase
    $ctx2 = "minecraft" ascii wide nocase
    $ctx3 = "javaw.exe" ascii wide nocase
    $ctx4 = "lunar" ascii wide nocase
    $ctx5 = "blockhit" ascii wide nocase

  condition:
    pe.is_pe and
    not dotnet.is_dotnet and
    filesize >= 350KB and
    filesize <= 1MB and
    pe.imports(/d3d9\.dll/i, /Direct3DCreate9/) > 0 and
    pe.imports(/imm32\.dll/i, /ImmGetContext/) > 0 and
    pe.imports(/user32\.dll/i, /(GetAsyncKeyState|GetCursorPos|GetKeyState|SetCursorPos|GetForegroundWindow)/) >= 4 and
    pe.imports(/kernel32\.dll/i, /(GetModuleHandleW|GetProcAddress|IsDebuggerPresent|SetUnhandledExceptionFilter)/) >= 4 and
    pe.imports(/winhttp\.dll/i, /./) == 0 and
    pe.imports(/wininet\.dll/i, /./) == 0 and
    1 of ($ctx*) and
    pe.number_of_imported_functions <= 400
}

rule Pack21_B1scoitoAuriumCluster : pack21 cheat clicker aurium b1scoito {
  meta:
    author = "Jumarf"
    description = "Pack21 cluster for Aurium and the b1scoito clicker lineage, including VM boot-protected builds"
    scope = "Content-only detection for the concrete pack21 families"

  condition:
    any of (
      _pack21_aurium_clicker,
      _pack21_b1scoito_family,
      _pack21_b1scoito_legacy_gui_variant,
      _pack21_vm_boot_variant
    )
}

private rule _pack22_ares_family {
  meta:
    author = "Jumarf"
    block = "pack22"
    role = "ares_clicker_family"

  strings:
    $a = "Ares.exe" ascii wide nocase
    $b = "AresLoader.Hooks" ascii wide nocase
    $c = "Ares" ascii wide nocase

  condition:
    pe.is_pe and
    filesize >= 5MB and
    2 of them
}

private rule _pack22_apollyon_clicker {
  meta:
    author = "Jumarf"
    block = "pack22"
    role = "apollyon_native_clicker"

  strings:
    $a = "[Apollyon]" ascii nocase
    $b = "By Kenyh" ascii nocase
    $c = "How much CPS do you want do? (Left Clicker)" ascii nocase
    $d = "How much CPS do you want do? (Right Clicker)" ascii nocase
    $e = "Apollyon sucefully destructed" ascii nocase

  condition:
    pe.is_pe and
    4 of them
}

private rule _pack22_ape_clicker {
  meta:
    author = "Jumarf"
    block = "pack22"
    role = "ape_native_clicker"

  strings:
    $a = "GetAsyncKeyState" ascii nocase
    $b = "GetCursorPos" ascii nocase
    $c = "SetCursorPos" ascii nocase

  condition:
    pe.is_pe and
    all of them and
    filesize <= 80KB
}

rule Pack22_AresApollyonCluster : pack22 cheat clicker ares apollyon {
  meta:
    author = "Jumarf"
    description = "Pack22 cluster for APE, Apollyon, and ARES clicker branches"
    scope = "Content-only detection for the concrete pack22 families while excluding bundled runtime DLLs"

  condition:
    any of (
      _pack22_ares_family,
      _pack22_apollyon_clicker,
      _pack22_ape_clicker
    )
}

private rule _pack23_1337clicker_bundle {
  meta:
    author = "Jumarf"
    block = "pack23"
    role = "1337clicker_bundle"

  strings:
    $a = "1337clicker/1.0.0" ascii nocase
    $b = "B1337clicker, Version=1.0.0.0" ascii nocase
    $c = "clr-namespace:_1337clicker" ascii nocase
    $d = "HWIDdisplay" ascii nocase
    $e = "1337clicker.dll" ascii nocase
    $f = "1337clicker" ascii nocase
    $g = "Confused" ascii nocase

  condition:
    (
      pe.is_pe and (
        3 of them or
        ($e and pe.pdb_path icontains "apphost")
      )
    ) or (
      not pe.is_pe and 2 of ($a, $e, $f, $g)
    )
}

private rule _pack23_ligma_clicker {
  meta:
    author = "Jumarf"
    block = "pack23"
    role = "ligma_clicker"

  strings:
    $a = "Ligma v1.0.1" ascii wide nocase
    $b = "Ligma" ascii wide nocase
    $c = "Lunar Client" ascii wide nocase
    $d = "Only Minecraft" ascii wide nocase

  condition:
    pe.is_pe and
    3 of them and
    pe.imports(/user32\.dll/i, /(GetAsyncKeyState|SetWindowsHookExA|SetCursorPos|GetCursorPos)/) > 0
}

private rule _pack23_lunar_clicker {
  meta:
    author = "Jumarf"
    block = "pack23"
    role = "lunar_clicker_family"

  strings:
    $a = "get_Lunar_Client_" ascii wide nocase
    $b = "clickerclass" ascii wide nocase
    $c = "Lunar Client\\Lunar Client\\clickerclass.cs" ascii wide nocase

  condition:
    (
      pe.is_pe and 2 of ($a, $b)
    ) or (
      not pe.is_pe and $c
    )
}

private rule _pack23_hwid_text_dump {
  meta:
    author = "Jumarf"
    block = "pack23"
    role = "hwid_crack_notes"

  strings:
    $a = "Credit to kyxles for finding their shitty list of hwids:" ascii nocase
    $b = "subscription still going with this shitty clicker" ascii nocase

  condition:
    not pe.is_pe and
    all of them
}

private rule _pack23_1337clicker_release_note {
  meta:
    author = "Jumarf"
    block = "pack23"
    role = "1337clicker_release_note"

  strings:
    $a = "Quated sent the executable" ascii nocase
    $b = "Whatify for finding the auth" ascii nocase
    $c = "Kyxles for cracking it" ascii nocase
    $d = "luvsy releases it" ascii nocase

  condition:
    not pe.is_pe and
    3 of them
}

private rule _pack23_1337clicker_crack_links {
  meta:
    author = "Jumarf"
    block = "pack23"
    role = "1337clicker_crack_links"

  strings:
    $a = "https://youtu.be/cKkAM10erxI" ascii nocase
    $b = "https://www.mediafire.com/file/pvgfji9k3s7u1r4/how+to+crack.mp4/file" ascii nocase

  condition:
    not pe.is_pe and
    all of them
}

rule Pack23_1337LigmaCluster : pack23 cheat clicker hwid lunar {
  meta:
    author = "Jumarf"
    description = "Pack23 cluster for 1337clicker, Ligma, Lunar clicker, and HWID crack artifacts"
    scope = "Content-only detection for the concrete pack23 families while excluding stock Microsoft/Guna libraries"

  condition:
    any of (
      _pack23_1337clicker_bundle,
      _pack23_ligma_clicker,
      _pack23_lunar_clicker,
      _pack23_hwid_text_dump,
      _pack23_1337clicker_release_note,
      _pack23_1337clicker_crack_links
    )
}

private rule _pack25_crown_bundle {
  meta:
    author = "Jumarf"
    block = "pack25"
    role = "crown_bundle"

  strings:
    $a = "launch Crown.exe ( you will need to open your minecraft before )" ascii nocase
    $b = "CrownClicker" ascii wide nocase
    $c = "CROWN" ascii wide nocase
    $d = "RebelionClicker Ghost Initialized!" ascii wide nocase
    $e = "RebelionClicker_Final.dll" ascii wide nocase

  condition:
    (
      pe.is_pe and 3 of ($b, $c, $d, $e)
    ) or (
      not pe.is_pe and $a
    )
}

private rule _pack25_stormy_family {
  meta:
    author = "Jumarf"
    block = "pack25"
    role = "stormy_injected_clicker"

  strings:
    $a = "right click on the java process > miscellaneous > inject dll > choose stormy" ascii nocase
    $b = "Stormy v0.1" ascii wide nocase
    $c = "net.minecraft.client.Minecraft" ascii wide nocase
    $d = "net.minecraft.client.gui.inventory.GuiInventory" ascii wide nocase

  condition:
    (
      pe.is_pe and 3 of ($b, $c, $d)
    ) or (
      not pe.is_pe and $a
    )
}

private rule _pack25_aion_clicker {
  meta:
    author = "Jumarf"
    block = "pack25"
    role = "aion_dotnet_clicker"

  strings:
    $a = "aion_ui" ascii wide nocase
    $b = "aion_main" ascii wide nocase
    $c = "CocaineClicker.Modules.Misc" ascii wide nocase
    $d = "CocaineClicker.Theme" ascii wide nocase
    $e = "LeftMinecraftOnly" ascii wide nocase
    $f = "RightMinecraftOnly" ascii wide nocase

  condition:
    pe.is_pe and
    dotnet.is_dotnet and
    4 of them
}

private rule _pack25_rebelion_server_script {
  meta:
    author = "Jumarf"
    block = "pack25"
    role = "rebelion_distribution_script"

  strings:
    $a = "@app.route(\"/public/RebelionClicker.dll\", methods=[\"GET\"])" ascii nocase
    $b = "dll_path = os.path.join(BASE_DIR, \"RebelionClicker.dll\")" ascii nocase

  condition:
    not pe.is_pe and
    all of them
}

private rule _pack25_crown_vm_loader {
  meta:
    author = "Jumarf"
    block = "pack25"
    role = "crown_vm_loader"

  condition:
    pe.is_pe and
    filesize >= 5MB and
    for any section in pe.sections : (
      section.name == ".boot" and
      section.raw_data_size >= 0x300000 and
      math.entropy(section.raw_data_offset, section.raw_data_size) >= 7.90
    )
}

rule Pack25_CrownStormyCluster : pack25 cheat clicker crown stormy {
  meta:
    author = "Jumarf"
    description = "Pack25 cluster for Crown, Rebelion, Stormy, Aion, and the accompanying delivery script"
    scope = "Content-only detection for the concrete pack25 families"

  condition:
    any of (
      _pack25_crown_bundle,
      _pack25_stormy_family,
      _pack25_aion_clicker,
      _pack25_rebelion_server_script,
      _pack25_crown_vm_loader
    )
}

private rule _pack26_atermys_family {
  meta:
    author = "Jumarf"
    block = "pack26"
    role = "atermys_internal_loader"

  strings:
    $a = "\\Atermys\\friends.json" ascii nocase
    $b = "\\Atermys\\configs\\" ascii nocase
    $c = "atermys internal.pdb" ascii nocase
    $d = "atermys loader.pdb" ascii nocase
    $e = "Waiting for minecraft" ascii nocase
    $f = "AutoClicker" ascii nocase
    $g = "RightClicker" ascii nocase

  condition:
    pe.is_pe and
    4 of them
}

private rule _pack26_crim_family {
  meta:
    author = "Jumarf"
    block = "pack26"
    role = "crim_sugma_family"

  strings:
    $a = "Crim v1.01" ascii wide nocase
    $b = "\\crim.dll" ascii wide nocase
    $c = "sugma-clicker" ascii wide nocase
    $d = "Minecraft Found:" ascii wide nocase

  condition:
    pe.is_pe and
    2 of them
}

private rule _pack26_toolbox_installer {
  meta:
    author = "Jumarf"
    block = "pack26"
    role = "toolbox_installer_wrapper"

  strings:
    $a = "PJC.pdb" ascii nocase
    $b = "###ClickerGui" ascii nocase
    $c = "spark-clicker.click" ascii nocase
    $d = "Minecraft" ascii nocase

  condition:
    pe.is_pe and
    3 of them and
    pe.imports(/kernel32\.dll/i, /(OpenProcess|ReadProcessMemory|WriteProcessMemory)/) > 0
}

private rule _pack26_bat_clicker_script {
  meta:
    author = "Jumarf"
    block = "pack26"
    role = "batch_clicker_script"

  strings:
    $a = "clicker v%version%" ascii nocase
    $b = "echo" ascii nocase

  condition:
    not pe.is_pe and
    $a and $b
}

rule Pack26_AtermysCrimCluster : pack26 cheat clicker loader atermys crim {
  meta:
    author = "Jumarf"
    description = "Pack26 cluster for Atermys, Crim, toolbox installer wrapper, and the batch clicker script"
    scope = "Content-only detection for the concrete pack26 families"

  condition:
    any of (
      _pack26_atermys_family,
      _pack26_crim_family,
      _pack26_toolbox_installer,
      _pack26_bat_clicker_script
    )
}

rule doomsday
{
    meta:
      author = "Jumarf"
      category = "doomsday"
      confidence = "high"
    strings:
        $h1 = { 18 f9 55 95 4e e4 58 64 86 2d 32 98 21 9e 8f 25 b7 36 10 05 4f dd cf 5c 5f e8 c5 d4 c7 92 33 2d d3 67 7d b8 82 68 38 73 86 3c 1a c2 00 30 1b 80 }
        $h2 = { 43 00 fb 82 21 94 50 23 02 bb f1 c4 9b b8 e4 67 7f ea 03 c2 d7 4c 49 d3 41 3a c6 f9 6b 49 b9 c2 33 ba 48 c8 8c 33 30 33 1d 18 06 79 1c 3b 3e 04 }
        $h3 = { 39 ff 32 b7 c5 72 17 eb d6 5a 6e 6c cc 14 40 d5 51 58 6d 2b dd c2 35 af ca 67 01 91 ac f9 2a ac c0 51 3d 35 f9 77 f5 a2 ed 3f 20 93 c8 f2 eb ec }
        $h4 = { b2 0b 03 f5 1c d7 46 30 ce 0a 5f 8f 70 a1 b7 f7 9b 73 3c 25 f0 86 f6 dc 23 9f 08 b5 d5 2e 30 2f 60 a8 15 4d f5 00 09 8f 30 28 a0 9f af 82 08 26 }
        $h5 = { 0a 18 bc 39 e6 12 d5 8f 5c 99 9c 55 8b e6 6f 3e fb 6c 5b 4c b9 84 17 96 4f 68 f4 e8 82 66 98 d7 ce 0f e6 3b 99 a2 f5 17 e8 c4 f3 71 95 e2 06 3f }
        $h6 = { 52 d4 66 0c 0d e4 a1 77 89 32 7d 4a b4 41 fd e1 3d ed 77 4a 1e 75 46 64 98 dc 59 0b 57 ba ed 5a 17 ee cb 68 28 a6 3a d1 7f 6b f5 f1 ec 4a 70 45 }
        $h7 = { aa 5c f9 c9 5f 12 69 22 40 b4 58 71 8e 4d 94 92 ab 58 25 ea 2b 7e 16 cf 0a 79 2b 70 9e ae 18 4f 91 32 55 c7 7e c3 db 4d 6e a2 81 23 ca 3f b4 09 }
        $h8 = { 88 87 17 e5 83 59 ca ce 04 61 dc 79 ec c2 25 b1 7f db 5c a7 50 d1 bd 08 6b 19 a1 1d 60 90 e4 ea ab 58 7c 8a d6 83 72 02 f2 e2 d3 b1 4d 6d 7d 42 }
        $h9 = { c5 19 a6 77 44 42 2d ed c3 bf 23 4f 0b e0 30 0c d5 5e 8b 25 3b 33 2a 3d ba cc 97 f6 11 da 2f fd f4 22 b1 2b 02 fd 71 1e 41 d6 26 cc 1b de 4a 17 }
        $h10 = { c4 0f be e5 b0 b1 fc b6 ac 98 a4 a3 b1 2c d6 8f a0 27 5d 92 78 df d8 6a 0e d4 77 b2 a3 f4 94 57 36 9f 4c 80 74 26 b4 e7 98 af cb fa 14 24 65 f5 }

    condition:
        1 of ($h*)
}


rule doomsday2
{
    meta:
      author = "Jumarf"
      category = "doomsday class"
      confidence = "medium"
    strings:
        $h1 = { 6e 65 74 2f 6a 61 76 61 2f 66 2e 63 6c 61 73 73 }
        $h2 = { 6E 65 74 2F 6A 61 76 61 2F 67 2E 63 6C 61 73 73 }
        $h3 = { 6E 65 74 2F 6A 61 76 61 2F 68 2E 63 6C 61 73 73 }
        $h4 = { 6E 65 74 2F 6A 61 76 61 2F 69 2E 63 6C 61 73 73 }
        $h5 = { 6E 65 74 2F 6A 61 76 61 2F 6B 2E 63 6C 61 73 73 }
        $h6 = { 6E 65 74 2F 6A 61 76 61 2F 6C 2E 63 6C 61 73 73 }
        $h7 = { 6E 65 74 2F 6A 61 76 61 2F 6D 2E 63 6C 61 73 73 }
        $h8 = { 6E 65 74 2F 6A 61 76 61 2F 72 2E 63 6C 61 73 73 }
        $h9 = { 6E 65 74 2F 6A 61 76 61 2F 73 2E 63 6C 61 73 73 }
        $h10 = { 6E 65 74 2F 6A 61 76 61 2F 74 2E 63 6C 61 73 73 }
        $h11 = { 6E 65 74 2F 6A 61 76 61 2F 79 2E 63 6C 61 73 73 }


    condition:
        2 of ($h*)
}