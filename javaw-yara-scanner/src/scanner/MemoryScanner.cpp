#include "scanner/MemoryScanner.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <queue>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <intrin.h>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace scanner {

// When set to 1 (define it in your debug build config, e.g. via a
// preprocessor define), ambiguous/generic-string detections get a
// Detection::details string showing the raw constant-pool header bytes
// that were checked, so a rare coincidental pool-validation pass can be
// told apart from an actual bug. Leave at 0 for release builds - it's an
// internal diagnostic, not something to show end users.
#ifndef SCANNER_DEBUG_DIAGNOSTICS
#define SCANNER_DEBUG_DIAGNOSTICS 0
#endif

using HitFn = std::function<void(int, size_t, size_t)>; // (patternIndex, startPos, patternLen)

struct AhoCorasick {
    struct State {
        int next[256];
        int fail;
        std::vector<std::pair<int, size_t>> output; // (patternIndex, patternLen)
        State() : fail(0) { std::fill(next, next + 256, -1); }
    };

    std::vector<State> states;

    AhoCorasick() {
        states.emplace_back();
    }

    void AddPattern(const std::string& pat, int patternIndex) {
        int cur = 0;
        for (unsigned char c : pat) {
            if (states[cur].next[c] == -1) {
                states[cur].next[c] = static_cast<int>(states.size());
                states.emplace_back();
            }
            cur = states[cur].next[c];
        }
        states[cur].output.emplace_back(patternIndex, pat.size());
    }

    void Build() {
        std::queue<int> q;
        for (int c = 0; c < 256; c++) {
            int s = states[0].next[c];
            if (s == -1) {
                states[0].next[c] = 0;
            } else {
                states[s].fail = 0;
                q.push(s);
            }
        }
        while (!q.empty()) {
            int r = q.front(); q.pop();
            for (const auto& out : states[states[r].fail].output)
                states[r].output.push_back(out);

            for (int c = 0; c < 256; c++) {
                int s = states[r].next[c];
                if (s == -1) {
                    states[r].next[c] = states[states[r].fail].next[c];
                } else {
                    states[s].fail = states[states[r].fail].next[c];
                    q.push(s);
                }
            }
        }
    }

    bool Search(const char* buf, size_t len, HitFn hit) const {
        int cur = 0;
        bool any = false;
        for (size_t i = 0; i < len; i++) {
            cur = states[cur].next[static_cast<unsigned char>(buf[i])];
            if (!states[cur].output.empty()) {
                for (const auto& out : states[cur].output) {
                    hit(out.first, i + 1 - out.second, out.second);
                    any = true;
                }
            }
        }
        return any;
    }
};

namespace {

static bool IsWordChar(char c) {
    unsigned char uc = static_cast<unsigned char>(c);
    return (uc >= 'a' && uc <= 'z') ||
           (uc >= 'A' && uc <= 'Z') ||
           (uc >= '0' && uc <= '9') ||
           uc == '_';
}

struct CpuInfo {
    int cores;
    int logicalProcessors;
    bool hasSSE2;
    bool hasAVX;
    bool hasAVX2;
    bool hasAVX512;
    size_t cacheSizeL3;
};

CpuInfo DetectCpuInfo() {
    CpuInfo info = {};

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    info.logicalProcessors = sysInfo.dwNumberOfProcessors;

    info.cores = info.logicalProcessors;

    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0);
    int maxLeaf = cpuInfo[0];

    if (maxLeaf >= 1) {
        __cpuid(cpuInfo, 1);
        info.hasSSE2 = (cpuInfo[3] & (1 << 26)) != 0;
        info.hasAVX = (cpuInfo[2] & (1 << 28)) != 0;
    }

    if (maxLeaf >= 7) {
        __cpuidex(cpuInfo, 7, 0);
        info.hasAVX2 = (cpuInfo[1] & (1 << 5)) != 0;
        info.hasAVX512 = (cpuInfo[1] & (1 << 16)) != 0;
    }

    if (maxLeaf >= 4) {
        for (int i = 0; i < 4; ++i) {
            __cpuidex(cpuInfo, 4, i);
            int cacheType = (cpuInfo[0] >> 5) & 0x7;
            if (cacheType == 3) {
                int ways = ((cpuInfo[1] >> 22) & 0x3FF) + 1;
                int partitions = ((cpuInfo[1] >> 12) & 0x3FF) + 1;
                int lineSize = (cpuInfo[1] & 0xFFF) + 1;
                int sets = cpuInfo[2] + 1;
                info.cacheSizeL3 = ways * partitions * lineSize * sets;
                break;
            }
        }
    }

    if (info.cacheSizeL3 == 0) {
        info.cacheSizeL3 = 8 * 1024 * 1024;
    }

    return info;
}

} // end anonymous namespace

struct ScanConfig {
    size_t chunkSize;
    int threadCount;
    bool useSIMD;
};

ScanConfig OptimizeScanConfig(const CpuInfo& cpu) {
    ScanConfig config = {};

    size_t optimalChunk = cpu.cacheSizeL3 / 4;
    config.chunkSize = std::clamp(optimalChunk, size_t(1 * 1024 * 1024), size_t(64 * 1024 * 1024));

    config.threadCount = std::min(cpu.logicalProcessors, cpu.cores * 2);
    config.threadCount = std::clamp(config.threadCount, 1, 16);

    config.useSIMD = cpu.hasAVX2 || cpu.hasAVX || cpu.hasSSE2;

    return config;
}

constexpr SIZE_T kDefaultChunkSize = 16 * 1024 * 1024;

std::string NormalizeFullwidthUnicode(const std::string& str) {
    std::string result;
    result.reserve(str.size());
    
    size_t i = 0;
    while (i < str.size()) {
        unsigned char byte1 = static_cast<unsigned char>(str[i]);
        
        if (byte1 == 0xEF && i + 2 < str.size()) {
            unsigned char byte2 = static_cast<unsigned char>(str[i + 1]);
            unsigned char byte3 = static_cast<unsigned char>(str[i + 2]);
            
            if (byte2 == 0xBC && byte3 >= 0xA1 && byte3 <= 0xBA) {
                result += static_cast<char>('A' + (byte3 - 0xA1));
                i += 3;
                continue;
            }
            if (byte2 == 0xBD && byte3 >= 0x81 && byte3 <= 0x9A) {
                result += static_cast<char>('a' + (byte3 - 0x81));
                i += 3;
                continue;
            }
            if (byte2 == 0xBC && byte3 >= 0x90 && byte3 <= 0x99) {
                result += static_cast<char>('0' + (byte3 - 0x90));
                i += 3;
                continue;
            }
        }
        
        result += str[i];
        i++;
    }
    
    return result;
}

const std::vector<std::string> kRedDetections = {
    // Strings of Disallowed Mods go here // Example: "MouseTweaks"
};

const std::vector<std::string> kYellowDetections = {
    // Strings of Generic Cheats go here // Example: "Auto Crystal"
};

const std::vector<std::string> kFullwidthObfuscatedCheats = {
    // Strings of Most common Generic Cheats go here // Example: "Autototem" ( This is in different fonts so it will detect stuff like dqrkis )
};

const std::vector<std::string> kJVMInjectionDetections = {
    // Strings of JVMInjections go here // Example: "-XX:+EnableDynamicAgentLoading"
};

const std::vector<std::string> kDNSCacheDetections = {
    // Strings of DNS Cache go here // Example: "vape.gg"
};

const std::vector<std::string> kWindowsServiceChecks = {
    "SysMain", "PcaSvc", "DPS", "EventLog", "Schedule", "Bam",
    "Dusmsvc", "Appinfo", "CDPSvc", "DcomLaunch", "PlugPlay", "wsearch"
};

const std::vector<std::string> kSystemTamperingDetections = {
    "ScriptBlockLogging", "EnableScriptBlockLogging", "ModuleLogging",
    "EnableModuleLogging", "EnableTranscripting", "Transcription",
    "wevtutil", "Clear-EventLog",
    "AppCompatCache", "ShimCache",
    "ExclusionPath",
    "JumpList", "AutomaticDestinations",
    "Start Menu\\Programs\\Startup"
};

const std::vector<std::string> kNormalScanStrings = [] {
    std::vector<std::string> all = kRedDetections;
    all.insert(all.end(), kYellowDetections.begin(), kYellowDetections.end());
    return all;
}();

const std::vector<std::string> kDeepScanStrings = [] {
    std::vector<std::string> all = kRedDetections;
    all.insert(all.end(), kYellowDetections.begin(), kYellowDetections.end());
    return all;
}();

struct ClientSignatureGroup {
    const char* label;
    std::vector<std::string> signatures;
};

const std::vector<ClientSignatureGroup> kClientSignatureGroups = {
    // like this { "Argon Client", { "dev/lvstrng/argon/", "another-string-if-needed-for-better-detection" }},
    // same goes for ofuscators
};

const std::unordered_set<std::string> kYellowLookup = [] {
    std::unordered_set<std::string> out;
    for (const auto& s : kYellowDetections) {
        out.insert(s);
    }
    return out;
}();


bool IsReadableProtection(DWORD protect) {
    constexpr DWORD mask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (protect & PAGE_GUARD) {
        return false;
    }
    return (protect & mask) != 0;
}

bool IsObfuscationSignature(const std::string& low) {
    return low.find("obfuscator") != std::string::npos ||
        low.find("mixin") != std::string::npos ||
        low.find("json") != std::string::npos;
}

struct CompiledSignature {
    std::string original;
    std::string lowered;
    Severity severity;
    char first{0};
    bool exactWord{true};
    bool ambiguous{false};
};


const std::vector<std::string>& NormalScanStrings() { return kNormalScanStrings; }
const std::vector<std::string>& DeepScanStrings() { return kDeepScanStrings; }

MemoryScanner::MemoryScanner() = default;

MemoryScanner::~MemoryScanner() {
    Cancel();
    if (m_worker.joinable()) {
        m_worker.join();
    }
}

void MemoryScanner::Start(uint32_t pid, const ScanOptions& options, std::string processStartTime) {
    Cancel();
    if (m_worker.joinable()) {
        m_worker.join();
    }

    m_cancel.store(false);
    m_running.store(true);
    m_progress.store(0.0f);
    m_lastError.clear();
    m_summary = {};
    m_summary.pid = pid;
    m_summary.processStartTime = std::move(processStartTime);
    m_summary.scanType = "Full";
    m_summary.generatedBy = options.generatedBy;

    m_worker = std::thread(&MemoryScanner::Worker, this, pid, options, m_summary.processStartTime);
}

void MemoryScanner::Cancel() {
    m_cancel.store(true);
}

bool MemoryScanner::IsRunning() const {
    return m_running.load();
}

float MemoryScanner::Progress() const {
    return m_progress.load();
}

scanner::ScanPhase MemoryScanner::GetPhase() const {
    return m_phase.load();
}

double MemoryScanner::GetPhaseElapsed() const {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration<double>(now - m_phaseStart).count();
}

const ScanSummary& MemoryScanner::Summary() const {
    return m_summary;
}

std::string MemoryScanner::LastError() const {
    return m_lastError;
}

void MemoryScanner::RegisterDetection(ScanSummary& summary, std::string key, Severity severity, uintptr_t address, uintptr_t baseAddress, std::string details) {
    for (auto& d : summary.detections) {
        if (d.message == key) {
            d.hits += 1;
            d.hitAddresses.push_back(address);
            if (d.baseAddress == 0) {
                d.baseAddress = baseAddress;
            }
            return;
        }
    }

    Detection d{};
    d.timestamp = NowTimestamp();
    d.message = std::move(key);
    d.details = std::move(details);
    d.severity = severity;
    d.address = address;
    d.baseAddress = baseAddress;
    d.hitAddresses.push_back(address);
    d.hits = 1;
    summary.detections.push_back(std::move(d));
}

static std::string ReadRemoteUnicodeString(HANDLE process, PVOID ustrAddr) {
    struct RemoteUStr {
        USHORT Length;
        USHORT MaximumLength;
        PVOID Buffer;
    };
    RemoteUStr us{};
    SIZE_T br = 0;
    if (!ReadProcessMemory(process, ustrAddr, &us, sizeof(us), &br) || !us.Buffer || us.Length == 0)
        return {};
    std::wstring w(static_cast<size_t>(us.Length / sizeof(wchar_t)), L'\0');
    if (!ReadProcessMemory(process, us.Buffer, w.data(), us.Length, &br))
        return {};
    std::string out;
    out.reserve(w.size());
    for (wchar_t c : w) out += (c > 0 && c < 128) ? static_cast<char>(c) : '?';
    return out;
}

static std::string ExtractJvmArgValue(const std::string& cmdLine, const std::string& sig) {
    std::string cmdLineLower = cmdLine;
    for (auto& c : cmdLineLower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    std::string sigLower = sig;
    for (auto& c : sigLower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    size_t pos = cmdLineLower.find(sigLower);
    if (pos == std::string::npos) return {};

    size_t end = pos + sig.length();
    while (end < cmdLine.size() && cmdLine[end] != ' ' && cmdLine[end] != '\t' && cmdLine[end] != '"' && cmdLine[end] != '\'') {
        end++;
    }

    return cmdLine.substr(pos, end - pos);
}

static std::string ReadJvmCommandLine(HANDLE process) {
    using NtQIP_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static auto NtQIP = reinterpret_cast<NtQIP_t>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));
    if (!NtQIP) return {};

    struct PBI {
        PVOID ExitStatus;
        PVOID PebBaseAddress;
        PVOID AffinityMask;
        PVOID BasePriority;
        PVOID UniqueProcessId;
        PVOID InheritedFromUniqueProcessId;
    };
    PBI pbi{};
    ULONG retLen = 0;
    if (NtQIP(process, 0, &pbi, sizeof(pbi), &retLen) != 0 || !pbi.PebBaseAddress)
        return {};

    PVOID procParams = nullptr;
    SIZE_T br = 0;
    if (!ReadProcessMemory(process,
            reinterpret_cast<BYTE*>(pbi.PebBaseAddress) + 0x20,
            &procParams, sizeof(procParams), &br) || !procParams)
        return {};

    std::string result = ReadRemoteUnicodeString(process,
        reinterpret_cast<BYTE*>(procParams) + 0x70);

    PVOID envPtr = nullptr;
    if (ReadProcessMemory(process,
            reinterpret_cast<BYTE*>(procParams) + 0x80,
            &envPtr, sizeof(envPtr), &br) && envPtr) {

        SIZE_T envSize = 0;
        if (!ReadProcessMemory(process,
                reinterpret_cast<BYTE*>(procParams) + 0x3F0,
                &envSize, sizeof(envSize), &br) || envSize == 0 || envSize > 512 * 1024)
            envSize = 64 * 1024;

        std::vector<wchar_t> env(envSize / sizeof(wchar_t), L'\0');
        if (ReadProcessMemory(process, envPtr, env.data(), envSize, &br) && br > 0) {
            for (size_t i = 0; i < env.size(); ++i) {
                if (env[i] == L'\0') {
                } else {
                    result += (env[i] > 0 && env[i] < 128) ? static_cast<char>(env[i]) : '?';
                }
            }
        }
    }

    return result;
}

// ---------------------------------------------------------------------
// Chat/log cross-reference for generic ("yellow") detections.
//
// Yellow-tier signatures are short, plausible-English module/setting names
// (e.g. "Autoclicker", "clickgui") that a legitimate player can type
// verbatim into in-game chat, a sign, a scoreboard, or a resource pack, and
// have that exact text end up sitting in the client's own memory. The
// constant-pool validation above already rules out most of those, but a
// residual class of false positives comes from the same word appearing,
// unvalidated, in memory that still happens to look word-bounded (freed
// buffers, chat history, etc). Minecraft's logs/latest.log records
// everything that goes through chat, so if a flagged yellow string also
// appears verbatim in that log, it's overwhelmingly more likely to be a
// chat message/username/sign than an actual cheat client component, and we
// drop it from the results instead of showing it to the operator.
// ---------------------------------------------------------------------

static std::string ReadRemoteProcessCurrentDirectory(HANDLE process) {
    using NtQIP_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static auto NtQIP = reinterpret_cast<NtQIP_t>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));
    if (!NtQIP) return {};

    struct PBI {
        PVOID ExitStatus;
        PVOID PebBaseAddress;
        PVOID AffinityMask;
        PVOID BasePriority;
        PVOID UniqueProcessId;
        PVOID InheritedFromUniqueProcessId;
    };
    PBI pbi{};
    ULONG retLen = 0;
    if (NtQIP(process, 0, &pbi, sizeof(pbi), &retLen) != 0 || !pbi.PebBaseAddress)
        return {};

    PVOID procParams = nullptr;
    SIZE_T br = 0;
    if (!ReadProcessMemory(process,
            reinterpret_cast<BYTE*>(pbi.PebBaseAddress) + 0x20,
            &procParams, sizeof(procParams), &br) || !procParams)
        return {};

    // CURDIR.DosPath (the process's current working directory) is a
    // UNICODE_STRING at offset 0x38 in RTL_USER_PROCESS_PARAMETERS on x64 -
    // the same undocumented layout this file already relies on for
    // CommandLine at 0x70 above. Every Minecraft launcher (vanilla,
    // PrismLauncher, MultiMC, CurseForge, Modrinth, ATLauncher, ...) sets
    // this to the instance's game directory before spawning javaw.exe, so
    // it's the most reliable way to find the right logs folder.
    return ReadRemoteUnicodeString(process, reinterpret_cast<BYTE*>(procParams) + 0x38);
}

static std::vector<std::filesystem::path> KnownLauncherRoots() {
    namespace fs = std::filesystem;
    std::vector<fs::path> roots;

    auto envDir = [](const char* name) -> std::string {
        char buf[MAX_PATH]{};
        DWORD n = GetEnvironmentVariableA(name, buf, MAX_PATH);
        return (n > 0 && n < MAX_PATH) ? std::string(buf) : std::string();
    };

    const std::string appData = envDir("APPDATA");
    const std::string userProfile = envDir("USERPROFILE");

    // Fallback locations, only consulted if the scanned process's own
    // working directory (see ReadRemoteProcessCurrentDirectory) didn't
    // yield a logs folder - e.g. the process handle couldn't be read, or
    // the launcher didn't set CWD to the instance root.
    if (!appData.empty()) {
        roots.push_back(fs::path(appData) / ".minecraft");
        roots.push_back(fs::path(appData) / "ModrinthApp" / "profiles");
        roots.push_back(fs::path(appData) / "PrismLauncher" / "instances");
        roots.push_back(fs::path(appData) / "MultiMC" / "instances");
        roots.push_back(fs::path(appData) / "ATLauncher" / "instances");
        roots.push_back(fs::path(appData) / ".feather" / "profiles");
    }
    if (!userProfile.empty()) {
        roots.push_back(fs::path(userProfile) / "curseforge" / "minecraft" / "Instances");
        roots.push_back(fs::path(userProfile) / ".lunarclient");
    }

    return roots;
}

// Given a root that might itself be a .minecraft game directory, or a
// folder of per-instance subfolders (each with their own logs, or their
// own nested .minecraft/logs), collect every logs/latest.log reachable
// from it, one level deep.
static void CollectLatestLogs(const std::filesystem::path& root,
                               std::vector<std::filesystem::path>& out) {
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::exists(root, ec)) return;

    auto direct = root / "logs" / "latest.log";
    if (fs::exists(direct, ec)) out.push_back(direct);

    auto nested = root / ".minecraft" / "logs" / "latest.log";
    if (fs::exists(nested, ec)) out.push_back(nested);

    if (fs::is_directory(root, ec)) {
        for (const auto& entry : fs::directory_iterator(root, ec)) {
            if (!entry.is_directory(ec)) continue;
            auto sub1 = entry.path() / "logs" / "latest.log";
            if (fs::exists(sub1, ec)) out.push_back(sub1);
            auto sub2 = entry.path() / ".minecraft" / "logs" / "latest.log";
            if (fs::exists(sub2, ec)) out.push_back(sub2);
        }
    }
}

static std::string ReadFileUtf8Lower(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    std::string content = ss.str();
    for (auto& c : content) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return content;
}

// Non-overlapping occurrence count of needle within haystack.
static std::size_t CountOccurrences(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) return 0;
    std::size_t count = 0;
    std::size_t pos = 0;
    while ((pos = haystack.find(needle, pos)) != std::string::npos) {
        ++count;
        pos += needle.size();
    }
    return count;
}

// Locates the scanned process's own game directory first, then falls back
// to known launcher directories, and returns whichever latest.log among
// the candidates was written to most recently.
static std::string FindLatestMinecraftLog(HANDLE process) {
    namespace fs = std::filesystem;
    std::vector<fs::path> candidates;

    std::string cwd = ReadRemoteProcessCurrentDirectory(process);
    if (!cwd.empty()) {
        CollectLatestLogs(fs::path(cwd), candidates);
    }

    if (candidates.empty()) {
        for (const auto& root : KnownLauncherRoots()) {
            CollectLatestLogs(root, candidates);
        }
    }

    if (candidates.empty()) return {};

    fs::path newest;
    fs::file_time_type newestTime{};
    bool have = false;
    std::error_code ec;
    for (const auto& c : candidates) {
        auto t = fs::last_write_time(c, ec);
        if (ec) continue;
        if (!have || t > newestTime) {
            newest = c;
            newestTime = t;
            have = true;
        }
    }

    return have ? newest.string() : std::string();
}

// Removes yellow/generic detections whose exact signature text also shows
// up in the player's own latest.log - i.e. it was typed in chat, is on a
// sign/scoreboard, or came from a resource pack, rather than being an
// actual cheat client string sitting in memory. Only Severity::Warning
// (the "yellow"/generic tier) is ever filtered this way; Detect and
// Suspicious detections are untouched.
//
// A string can legitimately show up in memory more times than it was
// typed in chat (e.g. it's also part of a real cheat module AND someone
// said it once), so this only clears as many memory hits as the log
// actually accounts for - one chat occurrence cancels out one memory hit,
// not the whole detection. The detection is only dropped entirely once
// every one of its hits has been explained by the log.
static void FilterChatFalsePositives(ScanSummary& summary, HANDLE process) {
    bool hasYellow = false;
    for (const auto& d : summary.detections) {
        if (d.severity == Severity::Warning) { hasYellow = true; break; }
    }
    if (!hasYellow) return;

    std::string logPath = FindLatestMinecraftLog(process);
    if (logPath.empty()) return;

    std::string logLower = ReadFileUtf8Lower(logPath);
    if (logLower.empty()) return;

    static const std::string kFoundSuffix = " found";

    for (auto it = summary.detections.begin(); it != summary.detections.end(); ) {
        if (it->severity != Severity::Warning) { ++it; continue; }

        std::string msgLower = it->message;
        for (auto& c : msgLower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (msgLower.size() > kFoundSuffix.size() &&
            msgLower.compare(msgLower.size() - kFoundSuffix.size(),
                              kFoundSuffix.size(), kFoundSuffix) == 0) {
            msgLower.resize(msgLower.size() - kFoundSuffix.size());
        }
        if (msgLower.empty()) { ++it; continue; }

        std::size_t chatOccurrences = CountOccurrences(logLower, msgLower);
        if (chatOccurrences == 0) { ++it; continue; }

        if (chatOccurrences >= it->hits) {
            // Every memory hit for this string is accounted for by the log.
            it = summary.detections.erase(it);
            continue;
        }

        // Only explain away as many hits as were actually seen in chat;
        // the remaining hits still get reported.
        it->hits -= chatOccurrences;
        if (it->hitAddresses.size() >= chatOccurrences) {
            it->hitAddresses.resize(it->hitAddresses.size() - chatOccurrences);
        }
        ++it;
    }
}

void MemoryScanner::Worker(uint32_t pid, ScanOptions options, std::string processStartTime) {
    (void)processStartTime;

    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!process) {
        m_lastError = "Access denied or process not found.";
        m_running.store(false);
        return;
    }

    auto recordPhase = [&](const std::string& name) {
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - m_phaseStart).count();
        if (!m_summary.phaseTimings.empty() || name == "Memory")
            m_summary.phaseTimings.push_back({name, elapsed});
        m_phaseStart = now;
    };
    m_phaseStart = std::chrono::steady_clock::now();

    CpuInfo cpu = DetectCpuInfo();
    ScanConfig config = OptimizeScanConfig(cpu);

    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    uintptr_t address = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    const uintptr_t endAddress = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    const auto& signatures = DeepScanStrings();

    std::vector<CompiledSignature> compiled;
    compiled.reserve(signatures.size() + kClientSignatureGroups.size() * 8 +
                     kJVMInjectionDetections.size() + kDNSCacheDetections.size() +
                     kSystemTamperingDetections.size());

    for (const auto& sig : signatures) {
        Severity sev = Severity::Detect;
        const std::string low = ToLower(sig);
        if (IsObfuscationSignature(low)) {
            sev = Severity::Suspicious;
        } else if (kYellowLookup.find(sig) != kYellowLookup.end()) {
            sev = Severity::Warning;
        } else if (low.find("mixin") != std::string::npos || low.find("json") != std::string::npos) {
            sev = Severity::Suspicious;
        } else if (low.find("injector") != std::string::npos) {
            sev = Severity::Warning;
        }
        if (low.empty()) {
            continue;
        }
        // Every generic/yellow signature requires strict isolation validation
        // (see isConstantPoolBacked in Worker()): it only counts as a real
        // detection when it's the whole content of a real compiled class
        // constant, not a substring or word embedded in surrounding text
        // (chat messages, other identifiers, etc).
        bool ambiguous = kYellowLookup.find(sig) != kYellowLookup.end();
        compiled.push_back({sig, low, sev, low[0], true, ambiguous});
    }

    for (const auto& group : kClientSignatureGroups) {
        bool isObfuscationGroup = (std::string(group.label).find("Obfuscator") != std::string::npos);
        Severity groupSeverity = isObfuscationGroup ? Severity::Suspicious : Severity::Detect;
        for (const auto& sig : group.signatures) {
            const std::string low = ToLower(sig);
            if (!low.empty()) {
                compiled.push_back({group.label, low, groupSeverity, low[0], false});
            }
        }
    }

    for (const auto& sig : kDNSCacheDetections) {
        const std::string low = ToLower(sig);
        if (!low.empty()) {
            compiled.push_back({sig + " (DNS Cache)", low, Severity::Detect, low[0], false});
        }
    }

    for (const auto& sig : kSystemTamperingDetections) {
        const std::string low = ToLower(sig);
        if (!low.empty()) {
            compiled.push_back({sig + " (System Tampering)", low, Severity::Suspicious, low[0], false});
        }
    }

    struct MemoryRegion {
        uintptr_t baseAddress;
        size_t size;
    };
    std::vector<MemoryRegion> regions;

    double totalBytes = 0.0;
    for (uintptr_t addr = address; addr < endAddress;) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(addr), &info, sizeof(info)) != sizeof(info)) {
            break;
        }
        if (info.State == MEM_COMMIT && IsReadableProtection(info.Protect) && info.Type == MEM_PRIVATE) {
            regions.push_back({reinterpret_cast<uintptr_t>(info.BaseAddress), info.RegionSize});
            totalBytes += static_cast<double>(info.RegionSize);
        }
        addr += info.RegionSize;
    }

    if (totalBytes <= 0.0 || regions.empty()) {
        m_summary = ScanSummary{pid, processStartTime, "full"};
        m_summary.generatedBy = options.generatedBy;
        m_progress.store(1.0f);
        m_running.store(false);
        CloseHandle(process);
        return;
    }

    std::vector<std::thread> threads;
    std::vector<ScanSummary> threadSummaries(config.threadCount, ScanSummary{pid, processStartTime, "full"});
    for (auto& summary : threadSummaries) {
        summary.generatedBy = options.generatedBy;
    }

    std::atomic<double> doneBytes{0.0};

    AhoCorasick ac;
    for (size_t i = 0; i < compiled.size(); i++)
        ac.AddPattern(compiled[i].lowered, static_cast<int>(i));
    ac.Build();

    std::atomic<size_t> nextRegion{0};

    auto scanRegion = [&](int threadId) {
        ScanSummary& localSummary = threadSummaries[threadId];

        std::vector<char> buffer(config.chunkSize);
        std::string lowerChunk;
        std::string normalizedChunk;
        lowerChunk.reserve(config.chunkSize);
        normalizedChunk.reserve(config.chunkSize);

        std::vector<bool> hitFlags(compiled.size(), false);

        size_t idx;
        while ((idx = nextRegion.fetch_add(1, std::memory_order_relaxed)) < regions.size()) {
            if (m_cancel.load()) break;

            const auto& region = regions[idx];
            uintptr_t regionAddr = region.baseAddress;
            size_t remaining = region.size;

            // Tail of the previous chunk *within this region*, so a match sitting
            // right at the start of a new chunk can still see the 3 bytes before
            // it for constant-pool header validation. Reset per region since the
            // previous region's tail bytes aren't contiguous with this one.
            std::array<unsigned char, 3> prevTail{};
            bool haveTail = false;

            while (remaining > 0 && !m_cancel.load()) {
                size_t toRead = std::min(config.chunkSize, remaining);
                SIZE_T bytesRead = 0;

                if (ReadProcessMemory(process,
                    reinterpret_cast<LPCVOID>(regionAddr),
                    buffer.data(), toRead, &bytesRead) && bytesRead > 0) {

                    lowerChunk.resize(bytesRead);
                    for (SIZE_T i = 0; i < bytesRead; ++i)
                        lowerChunk[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(buffer[i])));

                    normalizedChunk = NormalizeFullwidthUnicode(lowerChunk);

                    std::fill(hitFlags.begin(), hitFlags.end(), false);

                    // Returns the raw (untransformed) byte at position `rel`
                    // relative to the start of the current chunk. Negative
                    // positions reach back into prevTail. Returns -1 if that
                    // byte isn't available (start of the scan, tiny reads, etc).
                    auto rawByteAt = [&](long long rel) -> int {
                        if (rel >= 0) {
                            if (static_cast<SIZE_T>(rel) >= bytesRead) return -1;
                            return static_cast<unsigned char>(buffer[static_cast<size_t>(rel)]);
                        }
                        long long tailIdx = 3 + rel; // rel==-1 -> 2, -2 -> 1, -3 -> 0
                        if (!haveTail || tailIdx < 0 || tailIdx >= 3) return -1;
                        return prevTail[static_cast<size_t>(tailIdx)];
                    };

                    // A real compiled Java class embeds every identifier/string
                    // constant as: tag byte 0x01 (CONSTANT_Utf8), then a 2-byte
                    // big-endian length, then exactly that many bytes, then the
                    // *next* constant pool entry's own tag byte. Chat text
                    // sitting in a Netty/String buffer essentially never happens
                    // to have that header immediately before it, and checking the
                    // following tag too cuts the residual coincidence odds by
                    // roughly another 20x. Since our word-boundary check already
                    // pins down the full extent of the matched identifier, the
                    // declared length must equal the match length exactly.
                    auto isPlausibleConstantPoolTag = [](int tag) {
                        switch (tag) {
                            case 1: case 3: case 4: case 5: case 6: case 7: case 8:
                            case 9: case 10: case 11: case 12: case 15: case 16:
                            case 17: case 18: case 19: case 20:
                                return true;
                            default:
                                return false;
                        }
                    };

                    auto isConstantPoolBacked = [&](size_t start, size_t plen) {
                        long long base = static_cast<long long>(start);
                        int tag = rawByteAt(base - 3);
                        int lenHi = rawByteAt(base - 2);
                        int lenLo = rawByteAt(base - 1);
                        if (tag != 0x01 || lenHi < 0 || lenLo < 0) return false;
                        size_t declaredLen = (static_cast<size_t>(lenHi) << 8) | static_cast<size_t>(lenLo);
                        if (declaredLen != plen) return false;

                        // If we can see the byte right after the match (i.e. we're
                        // not sitting exactly at the end of this chunk), it must
                        // look like the start of the next constant pool entry.
                        int nextTag = rawByteAt(base + static_cast<long long>(plen));
                        if (nextTag >= 0 && !isPlausibleConstantPoolTag(nextTag)) return false;

                        return true;
                    };

                    auto exactHit = [&](const std::string& buf, int i, size_t start, size_t plen, bool rawAligned) {
                        if (hitFlags[i]) return;
                        bool poolValidated = false;
                        if (compiled[i].exactWord) {
                            bool beforeOk = (start == 0) || !IsWordChar(buf[start - 1]);
                            bool afterOk = (start + plen >= buf.size()) || !IsWordChar(buf[start + plen]);
                            if (!(beforeOk && afterOk)) return;

                            if (rawAligned) {
                                poolValidated = isConstantPoolBacked(start, plen);
                                // Ambiguous, plausibly-chat-typed words are only
                                // trusted when we can structurally confirm they
                                // sit inside real class bytecode. Everything else
                                // (obfuscated names, class paths, leetspeak/
                                // homoglyph variants) keeps the prior behavior.
                                if (compiled[i].ambiguous && !poolValidated) return;
                            } else if (compiled[i].ambiguous) {
                                // Homoglyph/fullwidth pass: offsets don't map back
                                // to raw memory, so pool validation isn't possible
                                // here. These variants aren't things a player
                                // types by accident, so keep them as before.
                            }
                        }
                        hitFlags[i] = true;

                        std::string details;
#if SCANNER_DEBUG_DIAGNOSTICS
                        if (rawAligned && compiled[i].ambiguous) {
                            long long base = static_cast<long long>(start);
                            int tag = rawByteAt(base - 3);
                            int lenHi = rawByteAt(base - 2);
                            int lenLo = rawByteAt(base - 1);
                            int nextTag = rawByteAt(base + static_cast<long long>(plen));
                            std::ostringstream oss;
                            oss << std::hex << std::setfill('0')
                                << "poolCheck tag=0x" << std::setw(2) << (tag < 0 ? 0 : tag)
                                << " len=0x" << std::setw(4) << ((lenHi < 0 || lenLo < 0) ? 0 : ((lenHi << 8) | lenLo))
                                << " nextTag=0x" << std::setw(2) << (nextTag < 0 ? 0 : nextTag)
                                << std::dec << " validated=" << (poolValidated ? "true" : "false");
                            details = oss.str();
                        }
#endif

                        RegisterDetection(localSummary,
                            compiled[i].original + " Found",
                            compiled[i].severity,
                            regionAddr, region.baseAddress, details);
                    };

                    ac.Search(lowerChunk.data(), lowerChunk.size(), [&](int i, size_t start, size_t plen) {
                        exactHit(lowerChunk, i, start, plen, /*rawAligned=*/true);
                    });

                    if (lowerChunk != normalizedChunk) {
                        ac.Search(normalizedChunk.data(), normalizedChunk.size(), [&](int i, size_t start, size_t plen) {
                            exactHit(normalizedChunk, i, start, plen, /*rawAligned=*/false);
                        });
                    }

                    if (bytesRead >= 3) {
                        prevTail[0] = static_cast<unsigned char>(buffer[bytesRead - 3]);
                        prevTail[1] = static_cast<unsigned char>(buffer[bytesRead - 2]);
                        prevTail[2] = static_cast<unsigned char>(buffer[bytesRead - 1]);
                        haveTail = true;
                    } else {
                        haveTail = false;
                    }
                }

                regionAddr += toRead;
                remaining -= toRead;

                doneBytes.fetch_add(static_cast<double>(toRead), std::memory_order_relaxed);
                const double p = doneBytes.load(std::memory_order_relaxed) / totalBytes;
                m_progress.store(static_cast<float>(std::clamp(p, 0.0, 1.0)));
            }
        }
    };

    for (int t = 0; t < config.threadCount; ++t)
        threads.emplace_back(scanRegion, t);

    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    ScanSummary finalSummary = threadSummaries[0];
    for (size_t i = 1; i < threadSummaries.size(); ++i) {
        finalSummary.detections.insert(
            finalSummary.detections.end(),
            threadSummaries[i].detections.begin(),
            threadSummaries[i].detections.end()
        );
    }

    // Ambiguous chat-typeable words are only ever registered above when
    // they're structurally confirmed to sit inside real compiled class bytecode
    // (see isConstantPoolBacked). As a second layer, cross-reference whatever
    // yellow/generic detections remain against the instance's own
    // logs/latest.log and drop any whose exact text was typed in chat
    // (usernames, messages, signs, resource packs, etc).
    FilterChatFalsePositives(finalSummary, process);

    for (const auto& d : finalSummary.detections) {
        if (d.severity == Severity::Detect) {
            finalSummary.detectCount += d.hits;
        } else if (d.severity == Severity::Warning) {
            finalSummary.warningCount += d.hits;
        } else {
            finalSummary.suspiciousCount += d.hits;
        }
    }

    {
        std::string cmdLine = ReadJvmCommandLine(process);
        if (!cmdLine.empty()) {
            std::string cmdLineLower = cmdLine;
            for (auto& c : cmdLineLower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

            for (const auto& sig : kJVMInjectionDetections) {
                std::string sigLower = ToLower(sig);
                if (cmdLineLower.find(sigLower) != std::string::npos) {
                    std::string argValue = ExtractJvmArgValue(cmdLine, sig);
                    RegisterDetection(finalSummary, sig, Severity::Warning, 0, 0, argValue);
                }
            }
        }
    }

    recordPhase("Memory");
    m_progress.store(0.0f);
    m_phase.store(ScanPhase::ServiceCheck);
    {
        std::vector<std::string> serviceIssues = CheckWindowsServices();
        size_t total = serviceIssues.size() + 1;
        for (size_t i = 0; i < serviceIssues.size(); ++i) {
            RegisterDetection(finalSummary, serviceIssues[i] + " (System Integrity)", Severity::Suspicious, 0, 0);
            m_progress.store(static_cast<float>(i + 1) / total);
        }
        std::vector<std::string> secureBootIssues = CheckSecureBoot();
        for (const auto& issue : secureBootIssues) {
            RegisterDetection(finalSummary, issue + " (System Integrity)", Severity::Suspicious, 0, 0);
        }
        m_progress.store(1.0f);
    }

    recordPhase("ServiceCheck");
    m_summary = std::move(finalSummary);
    m_progress.store(1.0f);
    m_running.store(false);
    CloseHandle(process);
}

std::string MemoryScanner::NowTimestamp() {
    std::time_t t = std::time(nullptr);
    std::tm local{};
    localtime_s(&local, &t);
    std::ostringstream oss;
    oss << std::setfill('0')
        << std::setw(2) << local.tm_hour << ":"
        << std::setw(2) << local.tm_min << ":"
        << std::setw(2) << local.tm_sec;
    return oss.str();
}

std::string MemoryScanner::ToLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::vector<std::string> MemoryScanner::CheckWindowsServices() {
    std::vector<std::string> stoppedServices;

    SC_HANDLE scManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scManager) {
        return stoppedServices;
    }

    for (const auto& serviceName : kWindowsServiceChecks) {
        SC_HANDLE service = OpenServiceA(scManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
        if (service) {
            SERVICE_STATUS status;
            if (QueryServiceStatus(service, &status)) {
                if (status.dwCurrentState != SERVICE_RUNNING) {
                    stoppedServices.push_back(serviceName + " (Service Not Running)");
                }
            }
            CloseServiceHandle(service);
        } else {
            stoppedServices.push_back(serviceName + " (Service Not Found)");
        }
    }

    CloseServiceHandle(scManager);
    return stoppedServices;
}

std::vector<std::string> MemoryScanner::CheckSecureBoot() {
    std::vector<std::string> issues;

    UINT32 secureBoot = 0;
    DWORD size = GetFirmwareEnvironmentVariableA(
        "SecureBoot",
        "{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
        &secureBoot,
        sizeof(secureBoot)
    );

    if (size > 0 && secureBoot == 0) {
        issues.push_back("SecureBoot (Disabled)");
    }

    return issues;
}

} // namespace scanner