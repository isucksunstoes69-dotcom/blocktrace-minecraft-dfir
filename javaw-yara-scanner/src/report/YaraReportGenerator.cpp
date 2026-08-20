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
    html << "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>P1AE javaw - Findings</title>"
         << "<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 50% 15%,#32111d 0,#12050b 45%,#050205 100%);color:#f2e8ee;font:13px 'DM Mono',Consolas,monospace;padding:18px}"
         << ".window{max-width:760px;margin:auto}.titlebar{height:34px;border-bottom:1px solid #4a1f31;display:flex;align-items:center;justify-content:space-between;color:#e7b8c5}.version{color:#b47a8c;font-size:11px}.title{letter-spacing:1px}.window-btn{color:#d68aa0;border:1px solid #642b42;padding:3px 8px;border-radius:4px}.card{margin:70px auto 0;background:rgba(25,5,14,.82);border:1px solid #71304b;border-radius:11px;padding:19px 22px;box-shadow:0 18px 70px #0009}.card h1{font-size:15px;text-align:center;font-weight:400;margin:0 0 14px;color:#f2d7e0}.meta{color:#a98091;font-size:11px;overflow-wrap:anywhere}.summary{display:flex;justify-content:center;gap:25px;color:#f1c2d0;margin:18px 0}.summary b{color:#ef6f8d}.rule-path{padding:10px;border-top:1px solid #4d2234;border-bottom:1px solid #4d2234}.progress{height:7px;background:#3a1424;border:1px solid #6c2c46;border-radius:4px;margin:15px 0 21px;overflow:hidden}.progress i{display:block;width:100%;height:100%;background:#e45d7d}.loading{text-align:center;color:#c99aaa;font-size:11px;margin-bottom:15px}table{width:100%;border-collapse:collapse}td,th{padding:9px 7px;border-bottom:1px solid #402030;text-align:left;font-size:11px}th{color:#a87789;font-weight:400;text-transform:uppercase}.hit{color:#ef6f8d;font-weight:700}.none{color:#9e7483}.footer{margin-top:17px;text-align:center;color:#80576a;font-size:10px}.strings,.matches{margin:18px 0}.strings h2,.matches h2{font-size:11px;font-weight:400;color:#a87789;letter-spacing:.08em}.chips{display:flex;flex-wrap:wrap;gap:7px}.chip{padding:6px 8px;border:1px solid #71304b;border-radius:4px;color:#f1b5c5;background:#2b0d1a}.log-row{display:flex;gap:9px;align-items:flex-start;padding:9px 10px;margin:6px 0;background:#1d0812;border:1px solid #4d2234;border-radius:6px;color:#edc2ce}.log-row .dot{width:7px;height:7px;margin-top:5px;border-radius:50%;background:#ef6f8d;box-shadow:0 0 10px #ef6f8d}.log-row code{font:11px Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}</style></head><body><main class='window'><header class='titlebar'><span class='version'>v1.11</span><span class='title'>P1AE javaw</span><span class='window-btn'>×</span></header><section class='card'>"
         << "<h1>BlockTrace Rule Findings</h1><div class='loading'>SCAN COMPLETE · INDICATORS REVIEWED</div><div class='progress'><i></i></div><p class='meta rule-path'>RULE FILE: " << Escape(result.path)
         << "</p><div class='summary'><span>RULES <b>" << result.ruleCount << "</b></span><span>STRINGS <b>"
         << result.stringCount << "</b></span></div><section class='strings'><h2>STRINGS FOUND</h2><div class='chips'>";
    for (const auto& value : result.foundStrings) html << "<span class='chip'>" << Escape(value) << "</span>";
    if (result.foundStrings.empty()) html << "<span class='meta'>No named YARA strings found.</span>";
    html << "</div></section><section class='matches'><h2>MATCHED SOURCE LINES</h2>";
    for (const auto& line : result.matchedLines) html << "<div class='log-row'><span class='dot'></span><code>" << Escape(line) << "</code></div>";
    if (result.matchedLines.empty()) html << "<p class='meta'>No configured indicator lines found.</p>";
    html << "</section><table><tr><th>Indicator</th><th>Occurrences</th><th>Status</th></tr>";
    for (const auto& item : result.indicators) {
        html << "<tr><td>" << Escape(item.indicator) << "</td><td>" << item.hits << "</td><td class='"
             << (item.hits ? "hit'>FOUND" : "none'>NOT FOUND") << "</td></tr>";
    }
    html << "</table><p class='footer'>Generated locally by BlockTrace Rule Scanner · findings shown from supplied text</p></section></main></body></html>";
    std::ofstream out(outputPath, std::ios::trunc); out << html.str();
    return outputPath;
}

void OpenInDefaultBrowser(const std::string& path) {
    ShellExecuteA(nullptr, "open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}
}

