#include "scanner/YaraRuleScanner.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <regex>
#include <sstream>

namespace scanner {
static std::string Lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}
ScanResult ScanRuleTextFile(const std::string& path) {
    ScanResult result{}; result.path = path;
    std::ifstream input(path, std::ios::binary);
    if (!input) { result.error = "Could not read the selected file."; return result; }
    std::ostringstream data; data << input.rdbuf();
    const std::string text = data.str(); const std::string lower = Lower(text);
    const std::regex ruleRegex(R"(\brule\s+[A-Za-z_][A-Za-z0-9_]*)", std::regex::icase);
    const std::regex stringRegex(R"(\$[A-Za-z_][A-Za-z0-9_]*)");
    result.ruleCount = static_cast<int>(std::distance(std::sregex_iterator(text.begin(), text.end(), ruleRegex), std::sregex_iterator()));
    result.stringCount = static_cast<int>(std::distance(std::sregex_iterator(text.begin(), text.end(), stringRegex), std::sregex_iterator()));
    const char* names[] = {"dnscache", "lsass.exe", "javaw.exe", "dcom", "sysmain", "pcasvc", "bam", "schedule", "eventlog", "dusmsvc", "dps", "cdpsvc"};
    for (const char* name : names) {
        int count = 0; size_t at = 0;
        while ((at = lower.find(name, at)) != std::string::npos) { ++count; at += std::strlen(name); }
        result.indicators.push_back({name, count});
    }
    result.ok = true; return result;
}
}
