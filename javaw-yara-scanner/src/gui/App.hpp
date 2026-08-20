#pragma once

#include "gui/Starfield.hpp"
#include "scanner/YaraRuleScanner.hpp"
#include <array>
#include <string>

struct GLFWwindow;

namespace gui {
class JavaApp {
public:
    JavaApp(); ~JavaApp();
    bool Initialize(); void Run(); void Shutdown();
private:
    void DrawTitleBar(); void DrawMainWindow(float dt); void BrowseForRuleFile(); void ScanRuleFile();
    GLFWwindow* m_window{};
    Starfield m_starfield;
    scanner::ScanResult m_result;
    std::array<char, 1024> m_rulePath{};
    std::string m_status{"Choose a readable rule file (.txt, .md, .json, .yml, .yaml)."};
    bool m_hasResult{false};
};
}
