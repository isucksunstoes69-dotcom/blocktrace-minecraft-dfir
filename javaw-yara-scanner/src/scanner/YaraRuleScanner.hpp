#pragma once
#include <string>
#include <vector>
namespace scanner {
struct IndicatorResult { std::string indicator; int hits{}; };
struct ScanResult { bool ok{}; std::string path; int ruleCount{}; int stringCount{}; std::vector<IndicatorResult> indicators; std::vector<std::string> foundStrings; std::vector<std::string> matchedLines; std::string error; };
ScanResult ScanRuleTextFile(const std::string& path);
}
