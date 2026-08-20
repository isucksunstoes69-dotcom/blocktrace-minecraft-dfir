#include "gui/App.hpp"
#include "gui/Theme.hpp"
#include "report/YaraReportGenerator.hpp"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <commdlg.h>
#include <dwmapi.h>
#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3.h>
#include <GLFW/glfw3native.h>
#include <GL/gl.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <algorithm>
#include <cmath>
#include <cstring>

namespace gui {
static constexpr int kWinW=720, kWinH=510;
namespace { void ApplyRoundedWindow(HWND h,int w,int he){ const int p=33,r=2; DwmSetWindowAttribute(h,p,&r,sizeof(r)); HRGN region=CreateRoundRectRgn(0,0,w+1,he+1,20,20); SetWindowRgn(h,region,TRUE); } }
JavaApp::JavaApp()=default; JavaApp::~JavaApp()=default;
bool JavaApp::Initialize(){ if(!glfwInit()) return false; glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR,3); glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR,3); glfwWindowHint(GLFW_OPENGL_PROFILE,GLFW_OPENGL_CORE_PROFILE); glfwWindowHint(GLFW_DECORATED,GLFW_FALSE); glfwWindowHint(GLFW_RESIZABLE,GLFW_FALSE); glfwWindowHint(GLFW_TRANSPARENT_FRAMEBUFFER,GLFW_TRUE); m_window=glfwCreateWindow(kWinW,kWinH,"BlockTrace Rule Scanner",nullptr,nullptr); if(!m_window)return false; glfwMakeContextCurrent(m_window); glfwSwapInterval(1); glfwSetWindowAttrib(m_window,GLFW_FLOATING,GLFW_TRUE); if(HWND h=glfwGetWin32Window(m_window)) ApplyRoundedWindow(h,kWinW,kWinH); IMGUI_CHECKVERSION(); ImGui::CreateContext(); ImGui::GetIO().ConfigFlags|=ImGuiConfigFlags_NavEnableKeyboard; ImGui::GetIO().IniFilename=nullptr; ImGui_ImplGlfw_InitForOpenGL(m_window,true); ImGui_ImplOpenGL3_Init("#version 330"); ApplyTheme(); m_starfield.Initialize(kWinW,kWinH); return true; }
void JavaApp::Shutdown(){ ImGui_ImplOpenGL3_Shutdown(); ImGui_ImplGlfw_Shutdown(); ImGui::DestroyContext(); if(m_window)glfwDestroyWindow(m_window); glfwTerminate(); }
void JavaApp::BrowseForRuleFile(){ char file[1024]{}; OPENFILENAMEA d{}; d.lStructSize=sizeof(d); d.hwndOwner=glfwGetWin32Window(m_window); d.lpstrFile=file; d.nMaxFile=sizeof(file); d.lpstrFilter="Readable rule text\0*.txt;*.md;*.json;*.yml;*.yaml\0All files\0*.*\0"; d.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST; if(GetOpenFileNameA(&d)){ strncpy_s(m_rulePath.data(),m_rulePath.size(),file,_TRUNCATE); m_status="Path loaded. Select START RULE SCAN."; m_hasResult=false; } }
void JavaApp::ScanRuleFile(){
    if(!m_rulePath[0]){m_status="Provide a readable rule-file path first.";return;}
    m_result=scanner::ScanRuleTextFile(m_rulePath.data()); m_hasResult=m_result.ok;
    if(!m_result.ok){m_status=m_result.error;return;}
    bool found=false; for(const auto& item:m_result.indicators) found|=item.hits>0;
    if(found){
        m_reportPath="BlockTraceRuleFindings.html";
        report::GenerateYaraHtmlReport(m_result,m_reportPath); report::OpenInDefaultBrowser(m_reportPath);
        m_status="Indicators found. Findings website opened in your default browser.";
    } else { m_reportPath.clear(); m_status="No requested indicators found in the selected rule file."; }
}
void JavaApp::DrawTitleBar(){ auto ws=ImGui::GetWindowSize(); auto* dl=ImGui::GetWindowDrawList(); auto wp=ImGui::GetWindowPos(); ImGui::SetCursorPos({12,8}); ImGui::TextColored({.45f,.44f,.54f,1},"v1.1"); const char* title="BlockTrace Rule Scanner"; auto ts=ImGui::CalcTextSize(title); ImGui::SetCursorPos({(ws.x-ts.x)/2,8}); ImGui::TextColored({.92f,.92f,.99f,1},"%s",title); dl->AddLine({wp.x+6,wp.y+27},{wp.x+ws.x-6,wp.y+27},IM_COL32(180,180,180,30)); ImGui::SetCursorPos({ws.x-28,6}); if(ImGui::Button("x##close",{18,16}))glfwSetWindowShouldClose(m_window,GLFW_TRUE); }
void JavaApp::DrawMainWindow(float){ ImGui::SetNextWindowPos({0,0}); ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize); ImGui::Begin("Root",nullptr,ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_NoMove); DrawTitleBar(); auto ws=ImGui::GetWindowSize(); auto* dl=ImGui::GetWindowDrawList(); ImVec2 card{ws.x-54,ws.y-58}, pos{27,40}, cp=ImGui::GetWindowPos(); dl->AddRectFilled({cp.x+pos.x,cp.y+pos.y},{cp.x+pos.x+card.x,cp.y+pos.y+card.y},IM_COL32(5,5,6,222),11); dl->AddRect({cp.x+pos.x,cp.y+pos.y},{cp.x+pos.x+card.x,cp.y+pos.y+card.y},IM_COL32(255,255,255,52),11); ImGui::SetCursorPos({pos.x+18,pos.y+16}); ImGui::TextColored({.92f,.92f,.99f,1},"YARA / TEXT RULE COVERAGE"); ImGui::SetCursorPos({pos.x+18,pos.y+41}); ImGui::TextDisabled("Reads .txt, .md, .json, .yml, or .yaml locally. No process-memory scan."); ImGui::SetCursorPos({pos.x+18,pos.y+74}); ImGui::TextDisabled("RULE PATH"); ImGui::SetCursorPos({pos.x+18,pos.y+94}); ImGui::SetNextItemWidth(card.x-145); ImGui::InputText("##rulepath",m_rulePath.data(),m_rulePath.size()); ImGui::SameLine(); if(ImGui::Button("BROWSE",{100,0}))BrowseForRuleFile(); ImGui::SetCursorPos({pos.x+18,pos.y+132}); if(ImGui::Button("START RULE SCAN",{card.x-36,28}))ScanRuleFile(); ImGui::SetCursorPos({pos.x+18,pos.y+170}); ImGui::TextColored(m_hasResult?ImVec4(.65f,.85f,.68f,1):ImVec4(.74f,.73f,.83f,1),"%s",m_status.c_str()); if(!m_reportPath.empty()){ ImGui::SameLine(); if(ImGui::SmallButton("OPEN REPORT")) report::OpenInDefaultBrowser(m_reportPath); } if(m_hasResult){ ImGui::SetCursorPos({pos.x+18,pos.y+206}); ImGui::Text("Rules: %d     String identifiers: %d",m_result.ruleCount,m_result.stringCount); ImGui::SetCursorPos({pos.x+18,pos.y+233}); if(ImGui::BeginTable("indicators",3,ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg,{card.x-36,164})){ ImGui::TableSetupColumn("Indicator");ImGui::TableSetupColumn("Hits");ImGui::TableSetupColumn("Status");ImGui::TableHeadersRow(); for(const auto& x:m_result.indicators){ImGui::TableNextRow();ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(x.indicator.c_str());ImGui::TableSetColumnIndex(1);ImGui::Text("%d",x.hits);ImGui::TableSetColumnIndex(2);ImGui::TextColored(x.hits?ImVec4(.65f,.85f,.68f,1):ImVec4(.75f,.5f,.5f,1),x.hits?"COVERED":"NOT FOUND");} ImGui::EndTable(); } } ImGui::End(); }
void JavaApp::Run(){float last=(float)glfwGetTime();while(!glfwWindowShouldClose(m_window)){glfwPollEvents();float now=(float)glfwGetTime(),dt=now-last;last=now;int w,h;glfwGetFramebufferSize(m_window,&w,&h);m_starfield.Resize(w,h);ImGui_ImplOpenGL3_NewFrame();ImGui_ImplGlfw_NewFrame();ImGui::NewFrame();m_starfield.Render(ImGui::GetBackgroundDrawList(),{0,0},{(float)w,(float)h},now);DrawMainWindow(dt);ImGui::Render();glViewport(0,0,w,h);glClear(GL_COLOR_BUFFER_BIT);ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());glfwSwapBuffers(m_window);}}
}

