#include "report/YaraReportGenerator.hpp"
#include <Windows.h>
#include <fstream>
#include <sstream>

namespace report {
static std::string Escape(const std::string& value) {
    std::string out;
    for (char c : value) {
        if (c == '&') out += "&amp;";
        else if (c == '<') out += "&lt;";
        else if (c == '>') out += "&gt;";
        else if (c == '"') out += "&quot;";
        else out += c;
    }
    return out;
}

std::string GenerateYaraHtmlReport(const scanner::ScanResult& result, const std::string& outputPath) {
    std::ostringstream html;
    html << "<!doctype html><html><head><meta charset='utf-8'><title>BlockTrace Rule Findings</title>"
         << "<style>body{margin:0;background:#090a0f;color:#ececf5;font:16px Segoe UI,Arial;padding:36px}"
         << ".card{max-width:900px;margin:auto;background:#151722;border:1px solid #45475b;border-radius:16px;padding:28px;box-shadow:0 18px 70px #000}"
         << "h1{margin-top:0}table{width:100%;border-collapse:collapse}td,th{padding:12px;border-bottom:1px solid #343646;text-align:left}"
         << ".hit{color:#7ee2a1;font-weight:700}.none{color:#e78383}.meta{color:#a5a6bc}</style></head><body><main class='card'>"
         << "<h1>BlockTrace Rule Findings</h1><p class='meta'>Rule file: " << Escape(result.path)
         << "</p><p>YARA rules: <b>" << result.ruleCount << "</b> &nbsp; String identifiers: <b>"
         << result.stringCount << "</b></p><table><tr><th>Indicator</th><th>Occurrences</th><th>Status</th></tr>";
    for (const auto& item : result.indicators) {
        html << "<tr><td>" << Escape(item.indicator) << "</td><td>" << item.hits << "</td><td class='"
             << (item.hits ? "hit'>FOUND" : "none'>NOT FOUND") << "</td></tr>";
    }
    html << "</table><p class='meta'>Generated locally by BlockTrace Rule Scanner.</p></main></body></html>";
    std::ofstream out(outputPath, std::ios::trunc); out << html.str();
    return outputPath;
}

void OpenInDefaultBrowser(const std::string& path) {
    ShellExecuteA(nullptr, "open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}
}
