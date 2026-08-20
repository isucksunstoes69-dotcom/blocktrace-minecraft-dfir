#pragma once

#include "gui/Starfield.hpp"
#include "scanner/YaraRuleScanner.hpp"
#include <array>
#include <atomic>
#include <chrono>
#include <thread>
#include <string>

struct GLFWwindow;

namespace gui {
class JavaApp {
public:
    JavaApp(); ~JavaApp();
    bool Initialize(); void Run(); void Shutdown();
private:
    void DrawTitleBar(); void DrawMainWindow(float dt); void DrawLoadingWindow(float dt); void BrowseForRuleFile(); void ScanRuleFile(); void FinishScan();
    GLFWwindow* m_window{};
    Starfield m_starfield;
    scanner::ScanResult m_result;
    std::array<char, 1024> m_rulePath{};
    std::string m_status{"Choose a readable rule file (.txt, .md, .json, .yml, .yaml)."};
    std::string m_reportPath;
    bool m_hasResult{false};
    std::thread m_scanThread;
    std::atomic_bool m_scanning{false};
    std::atomic_bool m_scanReady{false};
    std::chrono::steady_clock::time_point m_scanStarted{};
};
}
