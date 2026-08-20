#pragma once

#include "scanner/YaraRuleScanner.hpp"
#include <string>

namespace report {
std::string GenerateYaraHtmlReport(const scanner::ScanResult& result, const std::string& outputPath);
void OpenInDefaultBrowser(const std::string& path);
}
