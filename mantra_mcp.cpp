// mcp_bridge.cpp
// MANTRA AI MCP Bridge — Full Python mantra_mcp.py parity in C++
// Connects Claude Desktop, Cursor, Windsurf, Copilot, Cline, Aider, and any
// MCP-compatible AI agent to the MANTRA main.cpp server.
//
// Architecture:
//   AI Agent (stdin/stdout JSON-RPC) ──► mcp_bridge ──► main.cpp (HTTP :8888)
//
// Compile:
//   g++ -std=c++17 mcp_bridge.cpp -lcurl -o mantra_bridge
//
// Dependencies:
//   apt install libcurl4-openssl-dev
//   Headers: httplib.h, nlohmann/json.hpp (single-header, place alongside this
//   file)
//
// Usage (MCP JSON-RPC over stdin/stdout — all AI agents use this):
//   ./mantra_bridge [--server http://127.0.0.1:8888] [--timeout 300]
//   [--debug]
//
// MCP config snippets for each platform are at the bottom of this file.
// ============================================================================

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <curl/curl.h>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using json = nlohmann::json;

// ============================================================================
// Configuration — matches Python DEFAULT_MANTRA_SERVER /
// DEFAULT_REQUEST_TIMEOUT
// ============================================================================
static std::string g_server_url = "http://127.0.0.1:8888";
static int g_timeout_sec = 300;
static bool g_debug = false;

// ============================================================================
// ANSI Colors — matching Python MantraColors exactly
// ============================================================================
namespace Col {
const char *RESET = "\033[0m";
const char *BOLD = "\033[1m";
const char *RED = "\033[91m";
const char *GREEN = "\033[92m";
const char *YELLOW = "\033[93m";
const char *FIRE_RED = "\033[38;5;202m";
const char *HACKER_RED = "\033[38;5;196m";
const char *ELECTRIC_PURPLE = "\033[38;5;129m";
const char *CYBER_ORANGE = "\033[38;5;208m";
const char *CRIMSON = "\033[38;5;160m";
const char *BLOOD_RED = "\033[38;5;124m";
const char *RUBY = "\033[38;5;161m";
const char *SUCCESS = "\033[38;5;46m";
const char *WARNING = "\033[38;5;208m";
const char *ERR = "\033[38;5;196m";
const char *INFO = "\033[38;5;51m";
const char *CRITICAL = "\033[48;5;196m\033[38;5;15m\033[1m";
const char *VULN_HIGH = "\033[38;5;196m\033[1m";
const char *VULN_CRITICAL = "\033[48;5;124m\033[38;5;15m\033[1m";
const char *HL_GREEN = "\033[48;5;46m\033[38;5;16m";
const char *HL_RED = "\033[48;5;196m\033[38;5;15m";
const char *HL_YELLOW = "\033[48;5;226m\033[38;5;16m";
const char *HL_BLUE = "\033[48;5;51m\033[38;5;16m";
const char *TOOL_RECOVERY = "\033[38;5;129m\033[1m";
} // namespace Col

// ============================================================================
// Logging — stderr only (stdout is reserved for MCP JSON-RPC)
// Matches Python ColoredFormatter with emojis
// ============================================================================
static std::mutex g_log_mutex;

enum class Log { DEBUG, INFO, WARNING, ERROR, CRITICAL };

void log(Log lvl, const std::string &msg) {
  if (lvl == Log::DEBUG && !g_debug)
    return;
  std::lock_guard<std::mutex> lk(g_log_mutex);
  struct M {
    const char *color;
    const char *emoji;
    const char *label;
  };
  static const std::map<Log, M> meta = {
      {Log::DEBUG, {Col::INFO, "🔍", "[DEBUG]   "}},
      {Log::INFO, {Col::SUCCESS, "✅", "[INFO]    "}},
      {Log::WARNING, {Col::WARNING, "⚠️ ", "[WARNING] "}},
      {Log::ERROR, {Col::ERR, "❌", "[ERROR]   "}},
      {Log::CRITICAL, {Col::CRITICAL, "🔥", "[CRITICAL]"}},
  };
  auto &m = meta.at(lvl);
  // Use current time
  auto now = std::chrono::system_clock::now();
  auto t = std::chrono::system_clock::to_time_t(now);
  std::tm bt{};
  localtime_r(&t, &bt);
  char ts[24];
  strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &bt);
  std::cerr << "[🔥 MANTRA MCP] " << ts << " " << m.color << m.emoji << " "
            << m.label << Col::RESET << " " << msg << "\n";
}

// ============================================================================
// HTTP client — matches Python MANTRAClient.safe_post / safe_get
// ============================================================================
size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, std::string *out) {
  out->append((char *)ptr, size * nmemb);
  return size * nmemb;
}

json http_post(const std::string &endpoint, const json &payload) {
  CURL *curl = curl_easy_init();
  if (!curl)
    return {{"error", "curl init failed"}, {"success", false}};

  std::string url = g_server_url + "/" + endpoint;
  std::string body = payload.dump();
  std::string response;

  struct curl_slist *hdrs = nullptr;
  hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
  hdrs = curl_slist_append(hdrs, "User-Agent: MANTRA-MCP-Bridge/6.0");

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.size());
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)g_timeout_sec);

  log(Log::DEBUG, "POST " + url);
  CURLcode res = curl_easy_perform(curl);
  curl_slist_free_all(hdrs);
  curl_easy_cleanup(curl);

  if (res != CURLE_OK) {
    std::string err = "Request failed: " + std::string(curl_easy_strerror(res));
    log(Log::ERROR, "🚫 " + err);
    return {{"error", err}, {"success", false}};
  }
  try {
    return json::parse(response);
  } catch (...) {
    return {{"raw", response}, {"success", true}};
  }
}

json http_get(const std::string &endpoint,
              const std::map<std::string, std::string> &params = {}) {
  CURL *curl = curl_easy_init();
  if (!curl)
    return {{"error", "curl init failed"}, {"success", false}};

  std::string url = g_server_url + "/" + endpoint;
  if (!params.empty()) {
    CURL *esc = curl_easy_init();
    url += "?";
    for (auto &[k, v] : params) {
      char *ek = curl_easy_escape(esc, k.c_str(), (int)k.size());
      char *ev = curl_easy_escape(esc, v.c_str(), (int)v.size());
      url += std::string(ek) + "=" + std::string(ev) + "&";
      curl_free(ek);
      curl_free(ev);
    }
    url.pop_back();
    curl_easy_cleanup(esc);
  }
  std::string response;

  struct curl_slist *hdrs = nullptr;
  hdrs = curl_slist_append(hdrs, "User-Agent: MANTRA-MCP-Bridge/6.0");

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)g_timeout_sec);

  log(Log::DEBUG, "GET " + url);
  CURLcode res = curl_easy_perform(curl);
  curl_slist_free_all(hdrs);
  curl_easy_cleanup(curl);

  if (res != CURLE_OK) {
    std::string err = "Request failed: " + std::string(curl_easy_strerror(res));
    log(Log::ERROR, "🚫 " + err);
    return {{"error", err}, {"success", false}};
  }
  try {
    return json::parse(response);
  } catch (...) {
    return {{"raw", response}, {"success", true}};
  }
}

// ============================================================================
// Connection check — matches Python MANTRAClient.__init__ retry logic
// ============================================================================
bool check_connection() {
  const int MAX_RETRIES = 3;
  for (int i = 0; i < MAX_RETRIES; ++i) {
    try {
      log(Log::INFO, "🔗 Attempting connection to " + g_server_url +
                         " (attempt " + std::to_string(i + 1) + "/" +
                         std::to_string(MAX_RETRIES) + ")");
      auto r = http_get("health");
      if (r.contains("status") && r["status"] == "healthy") {
        std::string ver = r.contains("version") && r["version"].is_string()
                              ? r["version"].get<std::string>() : "?";
        int tools = r.contains("total_tools_available") && r["total_tools_available"].is_number()
                        ? r["total_tools_available"].get<int>() : 0;
        log(Log::INFO, "🎯 Connected! Version: " + ver +
                           " | Tools: " + std::to_string(tools));
        return true;
      }
    } catch (const std::exception &e) {
      log(Log::WARNING, "Connection check error: " + std::string(e.what()));
    }
    if (i < MAX_RETRIES - 1) {
      log(Log::WARNING, "🔌 Connection refused — retrying in 2s");
      std::this_thread::sleep_for(std::chrono::seconds(2));
    }
  }
  log(Log::ERROR, "❌ Failed to connect after " + std::to_string(MAX_RETRIES) +
                      " attempts");
  return false;
}

// ============================================================================
// Tool implementations — each matches a Python @mcp.tool() function exactly
// All POST to main.cpp endpoints on port 8888
// ============================================================================

// ── NETWORK SCANNING
// ──────────────────────────────────────────────────────────
json tool_nmap_scan(const json &a) {
  log(Log::INFO, std::string(Col::FIRE_RED) + "🔍 Initiating Nmap scan: " +
                     a.value("target", "") + Col::RESET);
  json p;
  p["target"] = a.value("target", "");
  p["scan_type"] = a.value("scan_type", "-sV");
  p["ports"] = a.value("ports", "");
  p["additional_args"] = a.value("additional_args", "");
  p["use_recovery"] = true;
  auto r = http_post("api/tools/nmap", p);
  if (r.value("success", false)) {
    log(Log::INFO, std::string(Col::SUCCESS) + "✅ Nmap completed for " +
                       a.value("target", "") + Col::RESET);
    if (r.value("recovery_info", json{}).value("recovery_applied", false))
      log(Log::INFO,
          std::string(Col::HL_YELLOW) + " Recovery applied " + Col::RESET);
  } else {
    log(Log::ERROR, std::string(Col::ERR) + "❌ Nmap failed for " +
                        a.value("target", "") + Col::RESET);
    if (r.value("human_escalation", false))
      log(Log::ERROR, std::string(Col::CRITICAL) +
                          " HUMAN ESCALATION REQUIRED " + Col::RESET);
  }
  return r;
}

json tool_nmap_advanced_scan(const json &a) {
  log(Log::INFO, "🔍 Starting Advanced Nmap: " + a.value("target", ""));
  json p;
  p["target"] = a.value("target", "");
  p["scan_type"] = a.value("scan_type", "-sS");
  p["ports"] = a.value("ports", "");
  p["timing"] = a.value("timing", "T4");
  p["nse_scripts"] = a.value("nse_scripts", "");
  p["os_detection"] = a.value("os_detection", false);
  p["version_detection"] = a.value("version_detection", false);
  p["aggressive"] = a.value("aggressive", false);
  p["stealth"] = a.value("stealth", false);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/nmap-advanced", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Advanced Nmap completed");
  else
    log(Log::ERROR, "❌ Advanced Nmap failed");
  return r;
}

json tool_rustscan_fast_scan(const json &a) {
  log(Log::INFO, "⚡ Starting Rustscan: " + a.value("target", ""));
  json p;
  p["target"] = a.value("target", "");
  p["ports"] = a.value("ports", "");
  p["ulimit"] = a.value("ulimit", 5000);
  p["batch_size"] = a.value("batch_size", 4500);
  p["timeout"] = a.value("timeout", 1500);
  p["scripts"] = a.value("scripts", false);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/rustscan", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Rustscan completed");
  else
    log(Log::ERROR, "❌ Rustscan failed");
  return r;
}

json tool_masscan_high_speed(const json &a) {
  log(Log::INFO, "🚀 Starting Masscan: " + a.value("target", "") +
                     " rate=" + std::to_string(a.value("rate", 1000)));
  json p;
  p["target"] = a.value("target", "");
  p["ports"] = a.value("ports", "1-65535");
  p["rate"] = a.value("rate", 1000);
  p["interface"] = a.value("interface", "");
  p["router_mac"] = a.value("router_mac", "");
  p["source_ip"] = a.value("source_ip", "");
  p["banners"] = a.value("banners", false);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/masscan", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Masscan completed");
  else
    log(Log::ERROR, "❌ Masscan failed");
  return r;
}

json tool_autorecon_comprehensive(const json &a) {
  log(Log::INFO, "🔄 Starting AutoRecon: " + a.value("target", ""));
  json p;
  p["target"] = a.value("target", "");
  p["output_dir"] = a.value("output_dir", "/tmp/autorecon");
  p["verbose"] = a.value("verbose", 0);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/autorecon", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ AutoRecon completed");
  else
    log(Log::ERROR, "❌ AutoRecon failed");
  return r;
}

json tool_arp_scan_discovery(const json &a) {
  log(Log::INFO, "🔍 Starting arp-scan: " + a.value("target", "local network"));
  json p;
  p["target"] = a.value("target", "");
  p["interface"] = a.value("interface", "");
  p["local_network"] = a.value("local_network", false);
  p["timeout"] = a.value("timeout", 500);
  p["retry"] = a.value("retry", 3);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/arp-scan", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ arp-scan completed");
  else
    log(Log::ERROR, "❌ arp-scan failed");
  return r;
}

json tool_nbtscan_netbios(const json &a) {
  log(Log::INFO, "🔍 Starting nbtscan: " + a.value("target", ""));
  json p;
  p["target"] = a.value("target", "");
  p["verbose"] = a.value("verbose", false);
  p["timeout"] = a.value("timeout", 2);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/nbtscan", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ nbtscan completed");
  else
    log(Log::ERROR, "❌ nbtscan failed");
  return r;
}

// ── WEB SCANNING
// ──────────────────────────────────────────────────────────────
json tool_gobuster_scan(const json &a) {
  log(Log::INFO, std::string(Col::CRIMSON) + "📁 Starting Gobuster " +
                     a.value("mode", "dir") + " scan: " + a.value("url", "") +
                     Col::RESET);
  json p;
  p["url"] = a.value("url", "");
  p["mode"] = a.value("mode", "dir");
  p["wordlist"] = a.value("wordlist", "/usr/share/wordlists/dirb/common.txt");
  p["additional_args"] = a.value("additional_args", "");
  p["use_recovery"] = true;
  auto r = http_post("api/tools/gobuster", p);
  if (r.value("success", false)) {
    log(Log::INFO,
        std::string(Col::SUCCESS) + "✅ Gobuster completed" + Col::RESET);
    if (r.value("recovery_info", json{}).value("recovery_applied", false))
      log(Log::INFO,
          std::string(Col::HL_YELLOW) + " Recovery applied " + Col::RESET);
  } else {
    log(Log::ERROR, std::string(Col::ERR) + "❌ Gobuster failed" + Col::RESET);
    std::string alt = r.value("alternative_tool_suggested", "");
    if (!alt.empty())
      log(Log::INFO, std::string(Col::HL_BLUE) +
                         " Alternative suggested: " + alt + " " + Col::RESET);
  }
  return r;
}

json tool_nuclei_scan(const json &a) {
  log(Log::INFO, std::string(Col::BLOOD_RED) + "🔬 Starting Nuclei scan: " +
                     a.value("target", "") + Col::RESET);
  json p;
  p["target"] = a.value("target", "");
  p["severity"] = a.value("severity", "");
  p["tags"] = a.value("tags", "");
  p["template"] = a.value("template", "");
  p["additional_args"] = a.value("additional_args", "");
  p["use_recovery"] = true;
  auto r = http_post("api/tools/nuclei", p);
  if (r.value("success", false)) {
    log(Log::INFO,
        std::string(Col::SUCCESS) + "✅ Nuclei completed" + Col::RESET);
    std::string out = r.value("stdout", "");
    if (out.find("CRITICAL") != std::string::npos)
      log(Log::WARNING, std::string(Col::CRITICAL) +
                            " CRITICAL vulnerabilities detected! " +
                            Col::RESET);
    else if (out.find("HIGH") != std::string::npos)
      log(Log::WARNING, std::string(Col::VULN_HIGH) +
                            " HIGH severity vulnerabilities found! " +
                            Col::RESET);
  } else
    log(Log::ERROR, std::string(Col::ERR) + "❌ Nuclei failed" + Col::RESET);
  return r;
}

json tool_dirb_scan(const json &a) {
  log(Log::INFO, "📁 Starting Dirb scan: " + a.value("url", ""));
  json p;
  p["url"] = a.value("url", "");
  p["wordlist"] = a.value("wordlist", "/usr/share/wordlists/dirb/common.txt");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/dirb", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Dirb completed");
  else
    log(Log::ERROR, "❌ Dirb failed");
  return r;
}

json tool_nikto_scan(const json &a) {
  log(Log::INFO, "🔬 Starting Nikto scan: " + a.value("target", ""));
  json p;
  p["target"] = a.value("target", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/nikto", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Nikto completed");
  else
    log(Log::ERROR, "❌ Nikto failed");
  return r;
}

json tool_sqlmap_scan(const json &a) {
  log(Log::INFO, "💉 Starting SQLMap scan: " + a.value("url", ""));
  json p;
  p["url"] = a.value("url", "");
  p["data"] = a.value("data", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/sqlmap", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ SQLMap completed");
  else
    log(Log::ERROR, "❌ SQLMap failed");
  return r;
}

json tool_wpscan_analyze(const json &a) {
  log(Log::INFO, "🔍 Starting WPScan: " + a.value("url", ""));
  json p;
  p["url"] = a.value("url", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/wpscan", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ WPScan completed");
  else
    log(Log::ERROR, "❌ WPScan failed");
  return r;
}

json tool_ffuf_scan(const json &a) {
  log(Log::INFO, "🔍 Starting FFuf " + a.value("mode", "directory") +
                     " fuzzing: " + a.value("url", ""));
  json p;
  p["url"] = a.value("url", "");
  p["wordlist"] = a.value("wordlist", "/usr/share/wordlists/dirb/common.txt");
  p["match_codes"] = a.value("match_codes", "200,204,301,302,307,401,403");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/ffuf", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ FFuf completed");
  else
    log(Log::ERROR, "❌ FFuf failed");
  return r;
}

json tool_feroxbuster_scan(const json &a) {
  log(Log::INFO, "🔍 Starting Feroxbuster scan: " + a.value("url", ""));
  json p;
  p["url"] = a.value("url", "");
  p["wordlist"] = a.value("wordlist", "/usr/share/wordlists/dirb/common.txt");
  p["threads"] = a.value("threads", 10);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/feroxbuster", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Feroxbuster completed");
  else
    log(Log::ERROR, "❌ Feroxbuster failed");
  return r;
}

json tool_dirsearch_scan(const json &a) {
  log(Log::INFO, "📁 Starting Dirsearch scan: " + a.value("url", ""));
  json p;
  p["url"] = a.value("url", "");
  p["extensions"] = a.value("extensions", "php,html,js,txt,xml,json");
  p["threads"] = a.value("threads", 30);
  p["recursive"] = a.value("recursive", false);
  p["wordlist"] = a.value("wordlist", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/dirsearch", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Dirsearch completed");
  else
    log(Log::ERROR, "❌ Dirsearch failed");
  return r;
}

json tool_dalfox_xss_scan(const json &a) {
  log(Log::INFO, "🎯 Starting Dalfox XSS scan: " + a.value("url", ""));
  json p;
  p["url"] = a.value("url", "");
  p["pipe_mode"] = a.value("pipe_mode", false);
  p["blind"] = a.value("blind", false);
  p["mining_dom"] = a.value("mining_dom", true);
  p["mining_dict"] = a.value("mining_dict", true);
  p["custom_payload"] = a.value("custom_payload", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/dalfox", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Dalfox completed");
  else
    log(Log::ERROR, "❌ Dalfox failed");
  return r;
}

json tool_xsser_scan(const json &a) {
  log(Log::INFO, "🔍 Starting XSSer scan: " + a.value("url", ""));
  json p;
  p["url"] = a.value("url", "");
  p["params"] = a.value("params", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/xsser", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ XSSer completed");
  else
    log(Log::ERROR, "❌ XSSer failed");
  return r;
}

json tool_wfuzz_scan(const json &a) {
  log(Log::INFO, "🔍 Starting Wfuzz scan: " + a.value("url", ""));
  json p;
  p["url"] = a.value("url", "");
  p["wordlist"] = a.value("wordlist", "/usr/share/wordlists/dirb/common.txt");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/wfuzz", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Wfuzz completed");
  else
    log(Log::ERROR, "❌ Wfuzz failed");
  return r;
}

json tool_dotdotpwn_scan(const json &a) {
  log(Log::INFO, "🔍 Starting DotDotPwn scan: " + a.value("target", ""));
  json p;
  p["target"] = a.value("target", "");
  p["module"] = a.value("module", "http");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/dotdotpwn", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ DotDotPwn completed");
  else
    log(Log::ERROR, "❌ DotDotPwn failed");
  return r;
}

json tool_wafw00f_scan(const json &a) {
  log(Log::INFO, "🛡️ Starting Wafw00f WAF detection: " + a.value("target", ""));
  json p;
  p["target"] = a.value("target", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/wafw00f", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Wafw00f completed");
  else
    log(Log::ERROR, "❌ Wafw00f failed");
  return r;
}

json tool_jaeles_vulnerability_scan(const json &a) {
  log(Log::INFO,
      "🔬 Starting Jaeles vulnerability scan: " + a.value("url", ""));
  json p;
  p["url"] = a.value("url", "");
  p["signatures"] = a.value("signatures", "");
  p["config"] = a.value("config", "");
  p["threads"] = a.value("threads", 20);
  p["timeout"] = a.value("timeout", 20);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/jaeles", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Jaeles completed");
  else
    log(Log::ERROR, "❌ Jaeles failed");
  return r;
}

// ── RECON / OSINT
// ──────────────────────────────────────────────────────────────
json tool_amass_scan(const json &a) {
  log(Log::INFO, "🔍 Starting Amass " + a.value("mode", "enum") + ": " +
                     a.value("domain", ""));
  json p;
  p["domain"] = a.value("domain", "");
  p["mode"] = a.value("mode", "enum");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/amass", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Amass completed");
  else
    log(Log::ERROR, "❌ Amass failed");
  return r;
}

json tool_subfinder_scan(const json &a) {
  log(Log::INFO, "🔍 Starting Subfinder: " + a.value("domain", ""));
  json p;
  p["domain"] = a.value("domain", "");
  p["silent"] = a.value("silent", true);
  p["all_sources"] = a.value("all_sources", false);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/subfinder", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Subfinder completed");
  else
    log(Log::ERROR, "❌ Subfinder failed");
  return r;
}

json tool_katana_crawl(const json &a) {
  log(Log::INFO, "⚔️  Starting Katana crawl: " + a.value("url", ""));
  json p;
  p["url"] = a.value("url", "");
  p["depth"] = a.value("depth", 3);
  p["js_crawl"] = a.value("js_crawl", true);
  p["form_extraction"] = a.value("form_extraction", true);
  p["output_format"] = a.value("output_format", "json");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/katana", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Katana crawl completed");
  else
    log(Log::ERROR, "❌ Katana crawl failed");
  return r;
}

json tool_gau_discovery(const json &a) {
  log(Log::INFO, "📡 Starting Gau URL discovery: " + a.value("domain", ""));
  json p;
  p["domain"] = a.value("domain", "");
  p["providers"] = a.value("providers", "wayback,commoncrawl,otx,urlscan");
  p["include_subs"] = a.value("include_subs", true);
  p["blacklist"] =
      a.value("blacklist", "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/gau", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Gau completed");
  else
    log(Log::ERROR, "❌ Gau failed");
  return r;
}

json tool_waybackurls_discovery(const json &a) {
  log(Log::INFO,
      "🕰️  Starting Waybackurls discovery: " + a.value("domain", ""));
  json p;
  p["domain"] = a.value("domain", "");
  p["get_versions"] = a.value("get_versions", false);
  p["no_subs"] = a.value("no_subs", false);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/waybackurls", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Waybackurls completed");
  else
    log(Log::ERROR, "❌ Waybackurls failed");
  return r;
}

json tool_hakrawler_crawl(const json &a) {
  log(Log::INFO, "🕷️ Starting Hakrawler crawling: " + a.value("url", ""));
  json p;
  p["url"] = a.value("url", "");
  p["depth"] = a.value("depth", 2);
  p["forms"] = a.value("forms", true);
  p["robots"] = a.value("robots", true);
  p["sitemap"] = a.value("sitemap", true);
  p["wayback"] = a.value("wayback", false);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/hakrawler", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Hakrawler crawling completed");
  else
    log(Log::ERROR, "❌ Hakrawler crawling failed");
  return r;
}

json tool_httpx_probe(const json &a) {
  log(Log::INFO,
      "🌍 Starting httpx probe: " + a.value("target", a.value("targets", "")));
  json p;
  p["target"] = a.value("target", a.value("targets", ""));
  p["probe"] = a.value("probe", true);
  p["tech_detect"] = a.value("tech_detect", false);
  p["status_code"] = a.value("status_code", false);
  p["content_length"] = a.value("content_length", false);
  p["title"] = a.value("title", false);
  p["web_server"] = a.value("web_server", false);
  p["threads"] = a.value("threads", 50);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/httpx", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ httpx probe completed");
  else
    log(Log::ERROR, "❌ httpx probe failed");
  return r;
}

json tool_arjun_parameter_discovery(const json &a) {
  log(Log::INFO,
      "🎯 Starting Arjun parameter discovery: " + a.value("url", ""));
  json p;
  p["url"] = a.value("url", "");
  p["method"] = a.value("method", "GET");
  p["wordlist"] = a.value("wordlist", "");
  p["delay"] = a.value("delay", 0);
  p["threads"] = a.value("threads", 25);
  p["stable"] = a.value("stable", false);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/arjun", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Arjun completed");
  else
    log(Log::ERROR, "❌ Arjun failed");
  return r;
}

json tool_paramspider_mining(const json &a) {
  log(Log::INFO, "🕷️  Starting ParamSpider mining: " + a.value("domain", ""));
  json p;
  p["domain"] = a.value("domain", "");
  p["level"] = a.value("level", 2);
  p["exclude"] =
      a.value("exclude", "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico");
  p["output"] = a.value("output", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/paramspider", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ ParamSpider completed");
  else
    log(Log::ERROR, "❌ ParamSpider failed");
  return r;
}

json tool_x8_parameter_discovery(const json &a) {
  log(Log::INFO, "🔍 Starting x8 parameter discovery: " + a.value("url", ""));
  json p;
  p["url"] = a.value("url", "");
  p["wordlist"] = a.value("wordlist", "");
  p["method"] = a.value("method", "GET");
  p["body"] = a.value("body", "");
  p["headers"] = a.value("headers", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/x8", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ x8 completed");
  else
    log(Log::ERROR, "❌ x8 failed");
  return r;
}

json tool_fierce_scan(const json &a) {
  log(Log::INFO, "🔍 Starting Fierce DNS recon: " + a.value("domain", ""));
  json p;
  p["domain"] = a.value("domain", "");
  p["dns_server"] = a.value("dns_server", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/fierce", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Fierce completed");
  else
    log(Log::ERROR, "❌ Fierce failed");
  return r;
}

json tool_dnsenum_scan(const json &a) {
  log(Log::INFO, "🔍 Starting DNSenum: " + a.value("domain", ""));
  json p;
  p["domain"] = a.value("domain", "");
  p["dns_server"] = a.value("dns_server", "");
  p["wordlist"] = a.value("wordlist", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/dnsenum", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ DNSenum completed");
  else
    log(Log::ERROR, "❌ DNSenum failed");
  return r;
}

json tool_anew_data_processing(const json &a) {
  log(Log::INFO, "📝 Starting anew data processing");
  json p;
  p["input_data"] = a.value("input_data", "");
  p["output_file"] = a.value("output_file", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/anew", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ anew completed");
  else
    log(Log::ERROR, "❌ anew failed");
  return r;
}

json tool_qsreplace_parameter_replacement(const json &a) {
  log(Log::INFO, "🔄 Starting qsreplace parameter replacement");
  json p;
  p["urls"] = a.value("urls", "");
  p["replacement"] = a.value("replacement", "FUZZ");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/qsreplace", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ qsreplace completed");
  else
    log(Log::ERROR, "❌ qsreplace failed");
  return r;
}

json tool_uro_url_filtering(const json &a) {
  log(Log::INFO, "🔍 Starting uro URL filtering");
  json p;
  p["urls"] = a.value("urls", "");
  p["whitelist"] = a.value("whitelist", "");
  p["blacklist"] = a.value("blacklist", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/uro", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ uro completed");
  else
    log(Log::ERROR, "❌ uro failed");
  return r;
}

// ── SMB / WINDOWS
// ──────────────────────────────────────────────────────────────
json tool_enum4linux_scan(const json &a) {
  log(Log::INFO, "🔍 Starting Enum4linux: " + a.value("target", ""));
  json p;
  p["target"] = a.value("target", "");
  p["additional_args"] = a.value("additional_args", "-a");
  auto r = http_post("api/tools/enum4linux", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Enum4linux completed");
  else
    log(Log::ERROR, "❌ Enum4linux failed");
  return r;
}

json tool_enum4linux_ng_advanced(const json &a) {
  log(Log::INFO, "🔍 Starting Enum4linux-ng: " + a.value("target", ""));
  json p;
  p["target"] = a.value("target", "");
  p["username"] = a.value("username", "");
  p["password"] = a.value("password", "");
  p["domain"] = a.value("domain", "");
  p["shares"] = a.value("shares", true);
  p["users"] = a.value("users", true);
  p["groups"] = a.value("groups", true);
  p["policy"] = a.value("policy", true);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/enum4linux-ng", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Enum4linux-ng completed");
  else
    log(Log::ERROR, "❌ Enum4linux-ng failed");
  return r;
}

json tool_smbmap_scan(const json &a) {
  log(Log::INFO, "🔍 Starting SMBMap: " + a.value("target", ""));
  json p;
  p["target"] = a.value("target", "");
  p["username"] = a.value("username", "");
  p["password"] = a.value("password", "");
  p["domain"] = a.value("domain", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/smbmap", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ SMBMap completed");
  else
    log(Log::ERROR, "❌ SMBMap failed");
  return r;
}

json tool_rpcclient_enumeration(const json &a) {
  log(Log::INFO, "🔍 Starting rpcclient: " + a.value("target", ""));
  json p;
  p["target"] = a.value("target", "");
  p["username"] = a.value("username", "");
  p["password"] = a.value("password", "");
  p["domain"] = a.value("domain", "");
  p["commands"] =
      a.value("commands", "enumdomusers;enumdomgroups;querydominfo");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/rpcclient", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ rpcclient completed");
  else
    log(Log::ERROR, "❌ rpcclient failed");
  return r;
}

json tool_netexec_scan(const json &a) {
  log(Log::INFO, "🔍 Starting NetExec " + a.value("protocol", "smb") +
                     " scan: " + a.value("target", ""));
  json p;
  p["target"] = a.value("target", "");
  p["protocol"] = a.value("protocol", "smb");
  p["username"] = a.value("username", "");
  p["password"] = a.value("password", "");
  p["hash"] = a.value("hash_value", a.value("hash", ""));
  p["module"] = a.value("module", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/netexec", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ NetExec completed");
  else
    log(Log::ERROR, "❌ NetExec failed");
  return r;
}

json tool_responder_credential_harvest(const json &a) {
  log(Log::INFO,
      "🔍 Starting Responder on interface: " + a.value("interface", "eth0"));
  json p;
  p["interface"] = a.value("interface", "eth0");
  p["analyze"] = a.value("analyze", false);
  p["wpad"] = a.value("wpad", true);
  p["force_wpad_auth"] = a.value("force_wpad_auth", false);
  p["fingerprint"] = a.value("fingerprint", false);
  p["duration"] = a.value("duration", 300);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/responder", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Responder completed");
  else
    log(Log::ERROR, "❌ Responder failed");
  return r;
}

// ── CREDENTIALS ──────────────────────────────────────────────────────────────
json tool_hydra_attack(const json &a) {
  log(Log::INFO, "🔑 Starting Hydra attack: " + a.value("target", "") + ":" +
                     a.value("service", "ssh"));
  json p;
  p["target"] = a.value("target", "");
  p["service"] = a.value("service", "ssh");
  p["username"] = a.value("username", "");
  p["username_file"] = a.value("username_file", "");
  p["password"] = a.value("password", "");
  p["password_file"] = a.value("password_file", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/hydra", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Hydra completed");
  else
    log(Log::ERROR, "❌ Hydra failed");
  return r;
}

json tool_john_crack(const json &a) {
  log(Log::INFO, "🔐 Starting John the Ripper: " + a.value("hash_file", ""));
  json p;
  p["hash_file"] = a.value("hash_file", "");
  p["wordlist"] = a.value("wordlist", "/usr/share/wordlists/rockyou.txt");
  p["format"] = a.value("format_type", a.value("format", ""));
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/john", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ John the Ripper completed");
  else
    log(Log::ERROR, "❌ John the Ripper failed");
  return r;
}

json tool_hashcat_crack(const json &a) {
  log(Log::INFO,
      "🔐 Starting Hashcat attack: mode " + a.value("attack_mode", "0"));
  json p;
  p["hash_file"] = a.value("hash_file", "");
  p["hash_type"] = a.value("hash_type", "0");
  p["attack_mode"] = a.value("attack_mode", "0");
  p["wordlist"] = a.value("wordlist", "/usr/share/wordlists/rockyou.txt");
  p["mask"] = a.value("mask", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/hashcat", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Hashcat completed");
  else
    log(Log::ERROR, "❌ Hashcat failed");
  return r;
}

json tool_hashpump_attack(const json &a) {
  log(Log::INFO, "🔐 Starting HashPump attack");
  json p;
  p["signature"] = a.value("signature", "");
  p["data"] = a.value("data", "");
  p["key_length"] = a.value("key_length", "");
  p["append_data"] = a.value("append_data", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/hashpump", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ HashPump completed");
  else
    log(Log::ERROR, "❌ HashPump failed");
  return r;
}

// ── EXPLOITATION
// ──────────────────────────────────────────────────────────────
json tool_metasploit_run(const json &a) {
  log(Log::INFO, "🚀 Starting Metasploit module: " + a.value("module", ""));
  json p;
  p["module"] = a.value("module", "");
  p["options"] = a.value("options", json::object());
  auto r = http_post("api/tools/metasploit", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Metasploit completed");
  else
    log(Log::ERROR, "❌ Metasploit failed");
  return r;
}

json tool_msfvenom_generate(const json &a) {
  log(Log::INFO,
      "🚀 Starting MSFVenom payload generation: " + a.value("payload", ""));
  json p;
  p["payload"] = a.value("payload", "");
  p["format"] = a.value("format_type", a.value("format", ""));
  p["output_file"] = a.value("output_file", "");
  p["encoder"] = a.value("encoder", "");
  p["iterations"] = a.value("iterations", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/msfvenom", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ MSFVenom completed");
  else
    log(Log::ERROR, "❌ MSFVenom failed");
  return r;
}

// ── BINARY ANALYSIS ──────────────────────────────────────────────────────────
json tool_gdb_analyze(const json &a) {
  log(Log::INFO, "🔧 Starting GDB analysis: " + a.value("binary", ""));
  json p;
  p["binary"] = a.value("binary", "");
  p["commands"] = a.value("commands", "");
  p["script_file"] = a.value("script_file", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/gdb", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ GDB analysis completed");
  else
    log(Log::ERROR, "❌ GDB analysis failed");
  return r;
}

json tool_gdb_peda_debug(const json &a) {
  log(Log::INFO, "🔧 Starting GDB-PEDA analysis");
  json p;
  p["binary"] = a.value("binary", "");
  p["commands"] = a.value("commands", "");
  p["attach_pid"] = a.value("attach_pid", 0);
  p["core_file"] = a.value("core_file", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/gdb-peda", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ GDB-PEDA completed");
  else
    log(Log::ERROR, "❌ GDB-PEDA failed");
  return r;
}

json tool_radare2_analyze(const json &a) {
  log(Log::INFO, "🔧 Starting Radare2 analysis: " + a.value("binary", ""));
  json p;
  p["binary"] = a.value("binary", "");
  p["commands"] = a.value("commands", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/radare2", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Radare2 completed");
  else
    log(Log::ERROR, "❌ Radare2 failed");
  return r;
}

json tool_ghidra_analysis(const json &a) {
  log(Log::INFO, "🔧 Starting Ghidra analysis: " + a.value("binary", ""));
  json p;
  p["binary"] = a.value("binary", "");
  p["project_name"] = a.value("project_name", "mantra_analysis");
  p["script_file"] = a.value("script_file", "");
  p["analysis_timeout"] = a.value("analysis_timeout", 300);
  p["output_format"] = a.value("output_format", "xml");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/ghidra", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Ghidra completed");
  else
    log(Log::ERROR, "❌ Ghidra failed");
  return r;
}

json tool_binwalk_analyze(const json &a) {
  log(Log::INFO, "🔧 Starting Binwalk analysis: " + a.value("file_path", ""));
  json p;
  p["file_path"] = a.value("file_path", "");
  p["extract"] = a.value("extract", false);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/binwalk", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Binwalk completed");
  else
    log(Log::ERROR, "❌ Binwalk failed");
  return r;
}

json tool_checksec_analyze(const json &a) {
  log(Log::INFO, "🔧 Starting Checksec analysis: " + a.value("binary", ""));
  json p;
  p["binary"] = a.value("binary", "");
  auto r = http_post("api/tools/checksec", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Checksec completed");
  else
    log(Log::ERROR, "❌ Checksec failed");
  return r;
}

json tool_strings_extract(const json &a) {
  log(Log::INFO, "🔧 Starting Strings extraction: " + a.value("file_path", ""));
  json p;
  p["file_path"] = a.value("file_path", "");
  p["min_len"] = a.value("min_len", 4);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/strings", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Strings completed");
  else
    log(Log::ERROR, "❌ Strings failed");
  return r;
}

json tool_xxd_hexdump(const json &a) {
  log(Log::INFO, "🔧 Starting XXD hex dump: " + a.value("file_path", ""));
  json p;
  p["file_path"] = a.value("file_path", "");
  p["offset"] = a.value("offset", "0");
  p["length"] = a.value("length", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/xxd", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ XXD completed");
  else
    log(Log::ERROR, "❌ XXD failed");
  return r;
}

json tool_objdump_analyze(const json &a) {
  log(Log::INFO, "🔧 Starting Objdump analysis: " + a.value("binary", ""));
  json p;
  p["binary"] = a.value("binary", "");
  p["disassemble"] = a.value("disassemble", true);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/objdump", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Objdump completed");
  else
    log(Log::ERROR, "❌ Objdump failed");
  return r;
}

json tool_ropgadget_search(const json &a) {
  log(Log::INFO, "🔧 Starting ROPgadget search: " + a.value("binary", ""));
  json p;
  p["binary"] = a.value("binary", "");
  p["gadget_type"] = a.value("gadget_type", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/ropgadget", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ ROPgadget completed");
  else
    log(Log::ERROR, "❌ ROPgadget failed");
  return r;
}

json tool_ropper_gadget_search(const json &a) {
  log(Log::INFO, "🔧 Starting ropper analysis: " + a.value("binary", ""));
  json p;
  p["binary"] = a.value("binary", "");
  p["gadget_type"] = a.value("gadget_type", "rop");
  p["quality"] = a.value("quality", 1);
  p["arch"] = a.value("arch", "");
  p["search_string"] = a.value("search_string", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/ropper", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ ropper completed");
  else
    log(Log::ERROR, "❌ ropper failed");
  return r;
}

json tool_one_gadget_search(const json &a) {
  log(Log::INFO,
      "🔧 Starting one_gadget analysis: " + a.value("libc_path", ""));
  json p;
  p["libc_path"] = a.value("libc_path", "");
  p["level"] = a.value("level", 1);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/one-gadget", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ one_gadget completed");
  else
    log(Log::ERROR, "❌ one_gadget failed");
  return r;
}

json tool_pwntools_exploit(const json &a) {
  log(Log::INFO,
      "🔧 Starting Pwntools exploit: " + a.value("exploit_type", "local"));
  json p;
  p["script_content"] = a.value("script_content", "");
  p["target_binary"] = a.value("target_binary", "");
  p["target_host"] = a.value("target_host", "");
  p["target_port"] = a.value("target_port", 0);
  p["exploit_type"] = a.value("exploit_type", "local");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/pwntools", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Pwntools exploit completed");
  else
    log(Log::ERROR, "❌ Pwntools exploit failed");
  return r;
}

json tool_angr_symbolic_execution(const json &a) {
  log(Log::INFO, "🔧 Starting angr analysis: " + a.value("binary", ""));
  json p;
  p["binary"] = a.value("binary", "");
  p["script_content"] = a.value("script_content", "");
  p["find_address"] = a.value("find_address", "");
  p["avoid_addresses"] = a.value("avoid_addresses", "");
  p["analysis_type"] = a.value("analysis_type", "symbolic");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/angr", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ angr completed");
  else
    log(Log::ERROR, "❌ angr failed");
  return r;
}

json tool_pwninit_setup(const json &a) {
  log(Log::INFO, "🔧 Starting pwninit setup: " + a.value("binary", ""));
  json p;
  p["binary"] = a.value("binary", "");
  p["libc"] = a.value("libc", "");
  p["ld"] = a.value("ld", "");
  p["template_type"] = a.value("template_type", "python");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/pwninit", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ pwninit completed");
  else
    log(Log::ERROR, "❌ pwninit failed");
  return r;
}

json tool_libc_database_lookup(const json &a) {
  log(Log::INFO, "🔧 Starting libc-database " + a.value("action", "find"));
  json p;
  p["action"] = a.value("action", "find");
  p["symbols"] = a.value("symbols", "");
  p["libc_id"] = a.value("libc_id", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/libc-database", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ libc-database completed");
  else
    log(Log::ERROR, "❌ libc-database failed");
  return r;
}

// ── FORENSICS / STEGO ────────────────────────────────────────────────────────
json tool_volatility_analyze(const json &a) {
  log(Log::INFO, "🧠 Starting Volatility analysis: " + a.value("plugin", ""));
  json p;
  p["memory_file"] = a.value("memory_file", "");
  p["plugin"] = a.value("plugin", "imageinfo");
  p["profile"] = a.value("profile", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/volatility", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Volatility completed");
  else
    log(Log::ERROR, "❌ Volatility failed");
  return r;
}

json tool_volatility3_analyze(const json &a) {
  log(Log::INFO, "🧠 Starting Volatility3 analysis: " + a.value("plugin", ""));
  json p;
  p["memory_file"] = a.value("memory_file", "");
  p["plugin"] = a.value("plugin", "");
  p["output_file"] = a.value("output_file", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/volatility3", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Volatility3 completed");
  else
    log(Log::ERROR, "❌ Volatility3 failed");
  return r;
}

json tool_foremost_carving(const json &a) {
  log(Log::INFO,
      "📁 Starting Foremost file carving: " + a.value("input_file", ""));
  json p;
  p["input_file"] = a.value("input_file", "");
  p["output_dir"] = a.value("output_dir", "/tmp/foremost_output");
  p["file_types"] = a.value("file_types", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/foremost", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Foremost completed");
  else
    log(Log::ERROR, "❌ Foremost failed");
  return r;
}

json tool_steghide_analysis(const json &a) {
  log(Log::INFO, "🖼️ Starting Steghide " + a.value("action", "extract") + ": " +
                     a.value("cover_file", ""));
  json p;
  p["action"] = a.value("action", "extract");
  p["cover_file"] = a.value("cover_file", "");
  p["embed_file"] = a.value("embed_file", "");
  p["passphrase"] = a.value("passphrase", "");
  p["output_file"] = a.value("output_file", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/steghide", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Steghide completed");
  else
    log(Log::ERROR, "❌ Steghide failed");
  return r;
}

json tool_exiftool_extract(const json &a) {
  log(Log::INFO, "📷 Starting ExifTool analysis: " + a.value("file_path", ""));
  json p;
  p["file_path"] = a.value("file_path", "");
  p["output_format"] = a.value("output_format", "");
  p["tags"] = a.value("tags", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/exiftool", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ ExifTool completed");
  else
    log(Log::ERROR, "❌ ExifTool failed");
  return r;
}

// ── CLOUD / CONTAINERS
// ────────────────────────────────────────────────────────
json tool_prowler_scan(const json &a) {
  log(Log::INFO, "☁️  Starting Prowler " + a.value("provider", "aws") +
                     " security assessment");
  json p;
  p["provider"] = a.value("provider", "aws");
  p["profile"] = a.value("profile", "default");
  p["region"] = a.value("region", "");
  p["checks"] = a.value("checks", "");
  p["output_dir"] = a.value("output_dir", "/tmp/prowler_output");
  p["output_format"] = a.value("output_format", "json");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/prowler", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Prowler assessment completed");
  else
    log(Log::ERROR, "❌ Prowler assessment failed");
  return r;
}

json tool_trivy_scan(const json &a) {
  log(Log::INFO, "🔍 Starting Trivy " + a.value("scan_type", "image") +
                     " scan: " + a.value("target", ""));
  json p;
  p["scan_type"] = a.value("scan_type", "image");
  p["target"] = a.value("target", "");
  p["output_format"] = a.value("output_format", "json");
  p["severity"] = a.value("severity", "");
  p["output_file"] = a.value("output_file", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/trivy", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Trivy completed");
  else
    log(Log::ERROR, "❌ Trivy failed");
  return r;
}

json tool_scout_suite_assessment(const json &a) {
  log(Log::INFO,
      "☁️  Starting Scout Suite " + a.value("provider", "aws") + " assessment");
  json p;
  p["provider"] = a.value("provider", "aws");
  p["profile"] = a.value("profile", "default");
  p["report_dir"] = a.value("report_dir", "/tmp/scout-suite");
  p["services"] = a.value("services", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/scout-suite", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Scout Suite completed");
  else
    log(Log::ERROR, "❌ Scout Suite failed");
  return r;
}

json tool_cloudmapper_analysis(const json &a) {
  log(Log::INFO, "☁️  Starting CloudMapper " + a.value("action", "collect"));
  json p;
  p["action"] = a.value("action", "collect");
  p["account"] = a.value("account", "");
  p["config"] = a.value("config", "config.json");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/cloudmapper", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ CloudMapper completed");
  else
    log(Log::ERROR, "❌ CloudMapper failed");
  return r;
}

json tool_pacu_exploitation(const json &a) {
  log(Log::INFO, "☁️  Starting Pacu AWS exploitation");
  json p;
  p["session_name"] = a.value("session_name", "mantra_session");
  p["modules"] = a.value("modules", "");
  p["regions"] = a.value("regions", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/pacu", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Pacu completed");
  else
    log(Log::ERROR, "❌ Pacu failed");
  return r;
}

json tool_kube_hunter_scan(const json &a) {
  log(Log::INFO, "☁️  Starting kube-hunter Kubernetes scan");
  json p;
  p["target"] = a.value("target", "");
  p["remote"] = a.value("remote", "");
  p["cidr"] = a.value("cidr", "");
  p["active"] = a.value("active", false);
  p["report"] = a.value("report", "json");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/kube-hunter", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ kube-hunter completed");
  else
    log(Log::ERROR, "❌ kube-hunter failed");
  return r;
}

json tool_kube_bench_cis(const json &a) {
  log(Log::INFO, "☁️  Starting kube-bench CIS benchmark");
  json p;
  p["targets"] = a.value("targets", "");
  p["version"] = a.value("version", "");
  p["output_format"] = a.value("output_format", "json");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/kube-bench", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ kube-bench completed");
  else
    log(Log::ERROR, "❌ kube-bench failed");
  return r;
}

json tool_docker_bench_security_scan(const json &a) {
  log(Log::INFO, "🐳 Starting Docker Bench Security assessment");
  json p;
  p["checks"] = a.value("checks", "");
  p["exclude"] = a.value("exclude", "");
  p["output_file"] = a.value("output_file", "/tmp/docker-bench-results.json");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/docker-bench-security", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Docker Bench Security completed");
  else
    log(Log::ERROR, "❌ Docker Bench Security failed");
  return r;
}

json tool_clair_vulnerability_scan(const json &a) {
  log(Log::INFO,
      "🐳 Starting Clair vulnerability scan: " + a.value("image", ""));
  json p;
  p["image"] = a.value("image", "");
  p["config"] = a.value("config", "/etc/clair/config.yaml");
  p["output_format"] = a.value("output_format", "json");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/clair", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Clair completed");
  else
    log(Log::ERROR, "❌ Clair failed");
  return r;
}

json tool_falco_runtime_monitoring(const json &a) {
  log(Log::INFO, "🛡️  Starting Falco runtime monitoring for " +
                     std::to_string(a.value("duration", 60)) + "s");
  json p;
  p["config_file"] = a.value("config_file", "/etc/falco/falco.yaml");
  p["rules_file"] = a.value("rules_file", "");
  p["output_format"] = a.value("output_format", "json");
  p["duration"] = a.value("duration", 60);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/falco", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Falco monitoring completed");
  else
    log(Log::ERROR, "❌ Falco monitoring failed");
  return r;
}

json tool_checkov_iac_scan(const json &a) {
  log(Log::INFO, "🔍 Starting Checkov IaC scan: " + a.value("directory", "."));
  json p;
  p["directory"] = a.value("directory", ".");
  p["framework"] = a.value("framework", "");
  p["check"] = a.value("check", "");
  p["skip_check"] = a.value("skip_check", "");
  p["output_format"] = a.value("output_format", "json");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/checkov", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Checkov completed");
  else
    log(Log::ERROR, "❌ Checkov failed");
  return r;
}

json tool_terrascan_iac_scan(const json &a) {
  log(Log::INFO, "🔍 Starting Terrascan IaC scan: " + a.value("iac_dir", "."));
  json p;
  p["scan_type"] = a.value("scan_type", "all");
  p["iac_dir"] = a.value("iac_dir", ".");
  p["output_format"] = a.value("output_format", "json");
  p["severity"] = a.value("severity", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/terrascan", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Terrascan completed");
  else
    log(Log::ERROR, "❌ Terrascan failed");
  return r;
}

// ── HTTP FRAMEWORK / BROWSER
// ──────────────────────────────────────────────────
json tool_http_framework_test(const json &a) {
  std::string action = a.value("action", "request");
  log(Log::INFO, std::string(Col::FIRE_RED) + "🔥 Starting HTTP Framework " +
                     action + ": " + a.value("url", "") + Col::RESET);
  json p;
  p["url"] = a.value("url", "");
  p["method"] = a.value("method", "GET");
  p["data"] = a.value("data", json::object());
  p["headers"] = a.value("headers", json::object());
  p["cookies"] = a.value("cookies", json::object());
  p["action"] = action;
  auto r = http_post("api/tools/http-framework", p);
  if (r.value("success", false)) {
    log(Log::INFO, std::string(Col::SUCCESS) + "✅ HTTP Framework " + action +
                       " completed" + Col::RESET);
    auto vulns =
        r.value("result", json{}).value("vulnerabilities", json::array());
    if (!vulns.empty())
      log(Log::INFO, std::string(Col::HL_RED) + " Found " +
                         std::to_string(vulns.size()) + " vulnerabilities " +
                         Col::RESET);
  } else
    log(Log::ERROR, std::string(Col::ERR) + "❌ HTTP Framework " + action +
                        " failed" + Col::RESET);
  return r;
}

json tool_browser_agent_inspect(const json &a) {
  std::string action = a.value("action", "navigate");
  log(Log::INFO, std::string(Col::CRIMSON) + "🌐 Starting Browser Agent " +
                     action + ": " + a.value("url", "") + Col::RESET);
  json p;
  p["url"] = a.value("url", "");
  p["headless"] = a.value("headless", true);
  p["wait_time"] = a.value("wait_time", 5);
  p["action"] = action;
  p["active_tests"] = a.value("active_tests", false);
  auto r = http_post("api/tools/browser-agent", p);
  if (r.value("success", false)) {
    log(Log::INFO, std::string(Col::SUCCESS) + "✅ Browser Agent " + action +
                       " completed" + Col::RESET);
    auto sec = r.value("result", json{}).value("security_analysis", json{});
    if (!sec.empty()) {
      int issues = sec.value("total_issues", 0);
      int score = sec.value("security_score", 0);
      if (issues > 0)
        log(Log::WARNING, std::string(Col::HL_YELLOW) +
                              " Security Issues: " + std::to_string(issues) +
                              " | Score: " + std::to_string(score) + "/100 " +
                              Col::RESET);
      else
        log(Log::INFO, std::string(Col::HL_GREEN) +
                           " No security issues | Score: " +
                           std::to_string(score) + "/100 " + Col::RESET);
    }
  } else
    log(Log::ERROR, std::string(Col::ERR) + "❌ Browser Agent " + action +
                        " failed" + Col::RESET);
  return r;
}

json tool_burpsuite_alternative_scan(const json &a) {
  log(Log::INFO, std::string(Col::BLOOD_RED) +
                     "🔥 Starting Burp Suite Alternative scan: " +
                     a.value("target", "") + Col::RESET);
  json p;
  p["target"] = a.value("target", "");
  p["scan_type"] = a.value("scan_type", "comprehensive");
  p["headless"] = a.value("headless", true);
  p["max_depth"] = a.value("max_depth", 3);
  p["max_pages"] = a.value("max_pages", 50);
  auto r = http_post("api/tools/burpsuite-alternative", p);
  if (r.value("success", false)) {
    log(Log::INFO, std::string(Col::SUCCESS) +
                       "✅ Burp Suite Alternative scan completed" + Col::RESET);
    auto summary = r.value("result", json{}).value("summary", json{});
    if (!summary.empty()) {
      log(Log::INFO, std::string(Col::HL_BLUE) + " SCAN SUMMARY " + Col::RESET);
      log(Log::INFO,
          "  📊 Pages: " + std::to_string(summary.value("pages_analyzed", 0)));
      log(Log::INFO,
          "  🚨 Vulnerabilities: " +
              std::to_string(summary.value("total_vulnerabilities", 0)));
      log(Log::INFO,
          "  🛡️  Score: " + std::to_string(summary.value("security_score", 0)) +
              "/100");
    }
  } else
    log(Log::ERROR, std::string(Col::ERR) +
                        "❌ Burp Suite Alternative scan failed" + Col::RESET);
  return r;
}

json tool_burpsuite_scan(const json &a) {
  log(Log::INFO, "🔍 Starting Burp Suite scan");
  json p;
  p["project_file"] = a.value("project_file", "");
  p["config_file"] = a.value("config_file", "");
  p["target"] = a.value("target", "");
  p["headless"] = a.value("headless", false);
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/burpsuite", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Burp Suite completed");
  else
    log(Log::ERROR, "❌ Burp Suite failed");
  return r;
}

json tool_zap_scan(const json &a) {
  log(Log::INFO, "🔍 Starting ZAP scan: " + a.value("target", ""));
  json p;
  p["target"] = a.value("target", "");
  p["scan_type"] = a.value("scan_type", "baseline");
  p["api_key"] = a.value("api_key", "");
  p["daemon"] = a.value("daemon", false);
  p["output_file"] = a.value("output_file", "");
  p["additional_args"] = a.value("additional_args", "");
  auto r = http_post("api/tools/zap", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ ZAP completed");
  else
    log(Log::ERROR, "❌ ZAP failed");
  return r;
}

// ── AI PAYLOADS
// ────────────────────────────────────────────────────────────────
json tool_ai_generate_payload(const json &a) {
  log(Log::INFO, std::string(Col::ELECTRIC_PURPLE) +
                     "🤖 Generating AI payloads for " +
                     a.value("attack_type", "xss") + " attack" + Col::RESET);
  json p;
  p["attack_type"] = a.value("attack_type", "xss");
  p["complexity"] = a.value("complexity", "basic");
  p["technology"] = a.value("technology", "");
  p["url"] = a.value("url", "");
  auto r = http_post("api/ai/generate_payload", p);
  if (r.value("success", false)) {
    auto pd = r.value("ai_payload_generation", json{});
    int cnt = pd.value("payload_count", 0);
    log(Log::INFO,
        "✅ Generated " + std::to_string(cnt) + " contextual payloads");
    auto payloads = pd.value("payloads", json::array());
    if (!payloads.empty()) {
      log(Log::INFO, "🎯 Sample payloads generated:");
      for (int i = 0; i < std::min((int)payloads.size(), 3); ++i) {
        std::string pl = payloads[i].value("payload", "");
        if (pl.size() > 50)
          pl = pl.substr(0, 50) + "...";
        log(Log::INFO,
            "   ├─ [" + payloads[i].value("risk_level", "?") + "] " + pl);
      }
    }
  } else
    log(Log::ERROR, "❌ AI payload generation failed");
  return r;
}

json tool_ai_test_payload(const json &a) {
  log(Log::INFO, "🧪 Testing AI payload against " + a.value("target_url", ""));
  json p;
  p["payload"] = a.value("payload", "");
  p["target_url"] = a.value("target_url", "");
  p["method"] = a.value("method", "GET");
  auto r = http_post("api/ai/test_payload", p);
  if (r.value("success", false)) {
    bool vuln =
        r.value("ai_analysis", json{}).value("potential_vulnerability", false);
    log(Log::INFO, "🔍 Payload test completed | Vulnerability: " +
                       std::string(vuln ? "YES" : "NO"));
    if (vuln)
      log(Log::WARNING, "⚠️  Potential vulnerability found!");
  } else
    log(Log::ERROR, "❌ Payload testing failed");
  return r;
}

json tool_ai_generate_attack_suite(const json &a) {
  std::string target_url = a.value("target_url", "");
  std::string attack_types_str = a.value("attack_types", "xss,sqli,lfi");
  log(Log::INFO, "🚀 Generating comprehensive attack suite for " + target_url);
  // Split attack types
  json result;
  result["target_url"] = target_url;
  result["payload_suites"] = json::object();
  result["summary"] = {
      {"total_payloads", 0}, {"high_risk_payloads", 0}, {"test_cases", 0}};
  std::istringstream ss(attack_types_str);
  std::string at;
  while (std::getline(ss, at, ',')) {
    at.erase(0, at.find_first_not_of(" \t"));
    at.erase(at.find_last_not_of(" \t") + 1);
    if (at.empty())
      continue;
    log(Log::INFO, "🤖 Generating " + at + " payloads...");
    json gen_p;
    gen_p["attack_type"] = at;
    gen_p["complexity"] = "advanced";
    gen_p["url"] = target_url;
    auto pr = http_post("api/ai/generate_payload", gen_p);
    if (pr.value("success", false)) {
      auto pd = pr.value("ai_payload_generation", json{});
      result["payload_suites"][at] = pd;
      int cnt = pd.value("payload_count", 0);
      result["summary"]["total_payloads"] =
          result["summary"]["total_payloads"].get<int>() + cnt;
    }
  }
  log(Log::INFO,
      "✅ Attack suite generated: " +
          std::to_string(result["summary"]["total_payloads"].get<int>()) +
          " payloads");
  return {{"success", true}, {"attack_suite", result}};
}

json tool_advanced_payload_generation(const json &a) {
  std::string at = a.value("attack_type", "rce");
  std::string el = a.value("evasion_level", "standard");
  log(Log::INFO, std::string(Col::FIRE_RED) + "🎯 Generating advanced " + at +
                     " payload | Evasion: " + el + Col::RESET);
  json p;
  p["attack_type"] = at;
  p["target_context"] = a.value("target_context", "");
  p["evasion_level"] = el;
  p["custom_constraints"] = a.value("custom_constraints", "");
  auto r = http_post("api/ai/advanced-payload-generation", p);
  if (r.value("success", false)) {
    auto pg = r.value("advanced_payload_generation", json{});
    log(Log::INFO, "✅ Generated " +
                       std::to_string(pg.value("payload_count", 0)) +
                       " advanced payloads");
    log(Log::INFO,
        "🛡️ Evasion Level Applied: " + pg.value("evasion_level", "none"));
  } else
    log(Log::ERROR, "❌ Advanced payload generation failed");
  return r;
}

// ── CVE INTELLIGENCE
// ──────────────────────────────────────────────────────────
json tool_monitor_cve_feeds(const json &a) {
  int hours = a.value("hours", 24);
  std::string sev = a.value("severity_filter", "HIGH,CRITICAL");
  log(Log::INFO, "🔍 Monitoring CVE feeds for last " + std::to_string(hours) +
                     "h | Severity: " + sev);
  json p;
  p["hours"] = hours;
  p["severity_filter"] = sev;
  p["keywords"] = a.value("keywords", "");
  auto r = http_post("api/vuln-intel/cve-monitor", p);
  if (r.value("success", false)) {
    int cnt = (int)r.value("cve_monitoring", json{})
                  .value("cves", json::array())
                  .size();
    int ea = (int)r.value("exploitability_analysis", json::array()).size();
    log(Log::INFO, "✅ Found " + std::to_string(cnt) + " CVEs with " +
                       std::to_string(ea) + " exploitability analyses");
  }
  return r;
}

json tool_generate_exploit_from_cve(const json &a) {
  log(Log::INFO, "🤖 Generating " + a.value("exploit_type", "poc") +
                     " exploit for " + a.value("cve_id", ""));
  json p;
  p["cve_id"] = a.value("cve_id", "");
  p["target_os"] = a.value("target_os", "");
  p["target_arch"] = a.value("target_arch", "x64");
  p["exploit_type"] = a.value("exploit_type", "poc");
  p["evasion_level"] = a.value("evasion_level", "none");
  auto r = http_post("api/vuln-intel/exploit-generate", p);
  if (r.value("success", false)) {
    auto ca = r.value("cve_analysis", json{});
    auto eg = r.value("exploit_generation", json{});
    log(Log::INFO, "📊 CVE Analysis: " + ca.value("exploitability_level", "?") +
                       " exploitability");
    log(Log::INFO,
        "🎯 Exploit Generation: " +
            std::string(eg.value("success", false) ? "SUCCESS" : "FAILED"));
  }
  return r;
}

json tool_discover_attack_chains(const json &a) {
  log(Log::INFO,
      "🔗 Discovering attack chains for " + a.value("target_software", ""));
  json p;
  p["target_software"] = a.value("target_software", "");
  p["attack_depth"] = std::max(1, std::min(a.value("attack_depth", 3), 5));
  p["include_zero_days"] = a.value("include_zero_days", false);
  auto r = http_post("api/vuln-intel/attack-chains", p);
  if (r.value("success", false)) {
    auto chains = r.value("attack_chain_discovery", json{})
                      .value("attack_chains", json::array());
    log(Log::INFO,
        "📊 Found " + std::to_string(chains.size()) + " attack chains");
  }
  return r;
}

json tool_research_zero_day_opportunities(const json &a) {
  log(Log::INFO, "🔬 Researching zero-day opportunities in " +
                     a.value("target_software", ""));
  json p;
  p["target_software"] = a.value("target_software", "");
  p["analysis_depth"] = a.value("analysis_depth", "standard");
  p["source_code_url"] = a.value("source_code_url", "");
  auto r = http_post("api/vuln-intel/zero-day-research", p);
  if (r.value("success", false)) {
    auto research = r.value("zero_day_research", json{});
    int cnt =
        (int)research.value("potential_vulnerabilities", json::array()).size();
    int rs = research.value("risk_assessment", json{}).value("risk_score", 0);
    log(Log::INFO,
        "📊 Found " + std::to_string(cnt) + " potential vulnerability areas");
    log(Log::INFO, "🎯 Risk Score: " + std::to_string(rs) + "/100");
  }
  return r;
}

json tool_correlate_threat_intelligence(const json &a) {
  std::string indicators_str = a.value("indicators", "");
  std::string timeframe = a.value("timeframe", "30d");
  if (timeframe != "7d" && timeframe != "30d" && timeframe != "90d" &&
      timeframe != "1y")
    timeframe = "30d";
  // Parse indicators
  json ind_list = json::array();
  std::istringstream ss(indicators_str);
  std::string ind;
  while (std::getline(ss, ind, ',')) {
    ind.erase(0, ind.find_first_not_of(" "));
    if (!ind.empty())
      ind_list.push_back(ind);
  }
  if (ind_list.empty())
    return {{"success", false}, {"error", "No valid indicators provided"}};
  log(Log::INFO, "🧠 Correlating threat intelligence for " +
                     std::to_string(ind_list.size()) + " indicators");
  json p;
  p["indicators"] = ind_list;
  p["timeframe"] = timeframe;
  p["sources"] = a.value("sources", "all");
  auto r = http_post("api/vuln-intel/threat-feeds", p);
  if (r.value("success", false)) {
    auto ti = r.value("threat_intelligence", json{});
    log(Log::INFO,
        "📊 Found " +
            std::to_string(
                (int)ti.value("correlations", json::array()).size()) +
            " threat correlations");
  }
  return r;
}

json tool_vulnerability_intelligence_dashboard(const json &) {
  log(Log::INFO, "📊 Generating vulnerability intelligence dashboard");
  auto r = http_post("api/intelligence/vulnerability-dashboard", {});
  if (r.value("success", false))
    log(Log::INFO, "✅ Vulnerability intelligence dashboard generated");
  return r;
}

json tool_threat_hunting_assistant(const json &a) {
  std::string env = a.value("target_environment", "");
  std::string focus = a.value("hunt_focus", "general");
  log(Log::INFO, "🔍 Generating threat hunting playbook for " + env +
                     " | Focus: " + focus);
  json p;
  p["target_environment"] = env;
  p["threat_indicators"] = a.value("threat_indicators", "");
  p["hunt_focus"] = focus;
  auto r = http_post("api/intelligence/threat-hunting", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Threat hunting playbook generated");
  return r;
}

// ── INTELLIGENCE ENGINE
// ────────────────────────────────────────────────────────
json tool_analyze_target_intelligence(const json &a) {
  log(Log::INFO,
      "🧠 Analyzing target intelligence for: " + a.value("target", ""));
  json p;
  p["target"] = a.value("target", "");
  auto r = http_post("api/intelligence/analyze-target", p);
  if (r.value("success", false)) {
    auto prof = r.value("target_profile", json{});
    log(Log::INFO, "✅ Target analysis completed - Type: " +
                       prof.value("target_type", "?") +
                       " Risk: " + prof.value("risk_level", "?"));
  } else
    log(Log::ERROR, "❌ Target analysis failed");
  return r;
}

json tool_select_optimal_tools_ai(const json &a) {
  log(Log::INFO, "🎯 Selecting optimal tools for " + a.value("target", "") +
                     " objective: " + a.value("objective", "comprehensive"));
  json p;
  p["target"] = a.value("target", "");
  p["objective"] = a.value("objective", "comprehensive");
  auto r = http_post("api/intelligence/select-tools", p);
  if (r.value("success", false)) {
    auto tools = r.value("selected_tools", json::array());
    std::string ts;
    for (int i = 0; i < std::min((int)tools.size(), 3); ++i) {
      if (i)
        ts += ", ";
      ts += tools[i].get<std::string>();
    }
    if (tools.size() > 3)
      ts += "...";
    log(Log::INFO,
        "✅ AI selected " + std::to_string(tools.size()) + " tools: " + ts);
  } else
    log(Log::ERROR, "❌ Tool selection failed");
  return r;
}

json tool_optimize_tool_parameters_ai(const json &a) {
  log(Log::INFO, "⚙️  Optimizing parameters for " + a.value("tool", "") +
                     " against " + a.value("target", ""));
  json p;
  p["target"] = a.value("target", "");
  p["tool"] = a.value("tool", "nmap");
  // Parse context
  json ctx;
  try {
    ctx = json::parse(a.value("context", "{}"));
  } catch (...) {
    ctx = json::object();
  }
  p["context"] = ctx;
  auto r = http_post("api/intelligence/optimize-parameters", p);
  if (r.value("success", false)) {
    auto params = r.value("optimized_parameters", json{});
    log(Log::INFO, "✅ Parameters optimized - " +
                       std::to_string(params.size()) +
                       " parameters configured");
  } else
    log(Log::ERROR, "❌ Parameter optimization failed");
  return r;
}

json tool_create_attack_chain_ai(const json &a) {
  log(Log::INFO,
      "⚔️  Creating AI-driven attack chain for " + a.value("target", ""));
  json p;
  p["target"] = a.value("target", "");
  p["objective"] = a.value("objective", "comprehensive");
  auto r = http_post("api/intelligence/create-attack-chain", p);
  if (r.value("success", false)) {
    auto chain = r.value("attack_chain", json{});
    int steps = (int)chain.value("steps", json::array()).size();
    double prob = chain.value("success_probability", 0.0);
    int et = chain.value("estimated_time", 0);
    log(Log::INFO, "✅ Attack chain created - " + std::to_string(steps) +
                       " steps, " + std::to_string(prob) + " success prob, ~" +
                       std::to_string(et) + "s");
  } else
    log(Log::ERROR, "❌ Attack chain creation failed");
  return r;
}

json tool_intelligent_smart_scan(const json &a) {
  log(Log::INFO, std::string(Col::FIRE_RED) +
                     "🚀 Starting intelligent smart scan for " +
                     a.value("target", "") + Col::RESET);
  json p;
  p["target"] = a.value("target", "");
  p["objective"] = a.value("objective", "comprehensive");
  p["max_tools"] = a.value("max_tools", 5);
  auto r = http_post("api/intelligence/smart-scan", p);
  if (r.value("success", false)) {
    auto sr = r.value("scan_results", json{});
    auto es = sr.value("execution_summary", json{});
    log(Log::INFO, std::string(Col::SUCCESS) + "✅ Intelligent scan completed" +
                       Col::RESET);
    log(Log::INFO,
        std::string(Col::CYBER_ORANGE) + "📊 Execution Summary:" + Col::RESET);
    log(Log::INFO,
        "   • Tools: " + std::to_string(es.value("successful_tools", 0)) + "/" +
            std::to_string(es.value("total_tools", 0)));
    log(Log::INFO, "   • Success rate: " +
                       std::to_string(es.value("success_rate", 0.0)) + "%");
    int vulns = sr.value("total_vulnerabilities", 0);
    if (vulns > 0)
      log(Log::WARNING, std::string(Col::VULN_HIGH) + "🚨 " +
                            std::to_string(vulns) +
                            " vulnerabilities detected!" + Col::RESET);
  } else
    log(Log::ERROR, std::string(Col::ERR) + "❌ Intelligent scan failed: " +
                        r.value("error", "?") + Col::RESET);
  return r;
}

json tool_detect_technologies_ai(const json &a) {
  log(Log::INFO, "🔍 Detecting technologies for " + a.value("target", ""));
  json p;
  p["target"] = a.value("target", "");
  auto r = http_post("api/intelligence/technology-detection", p);
  if (r.value("success", false)) {
    auto techs = r.value("detected_technologies", json::array());
    std::string ts;
    for (auto &t : techs) {
      if (!ts.empty())
        ts += ",";
      ts += t.get<std::string>();
    }
    std::string cms = r.value("cms_type", "");
    log(Log::INFO, "✅ Technology detection completed - Technologies: " + ts +
                       (cms.empty() ? "" : ", CMS: " + cms));
  } else
    log(Log::ERROR, "❌ Technology detection failed");
  return r;
}

json tool_ai_reconnaissance_workflow(const json &a) {
  std::string target = a.value("target", ""),
              depth = a.value("depth", "standard");
  log(Log::INFO, "🕵️  Starting AI reconnaissance workflow for " + target +
                     " (depth: " + depth + ")");
  std::string objective = (depth == "deep")      ? "comprehensive"
                          : (depth == "surface") ? "quick"
                                                 : "comprehensive";
  int max_tools = (depth == "deep") ? 8 : (depth == "surface") ? 3 : 5;
  auto analysis =
      http_post("api/intelligence/analyze-target", {{"target", target}});
  if (!analysis.value("success", false))
    return analysis;
  auto chain = http_post("api/intelligence/create-attack-chain",
                         {{"target", target}, {"objective", objective}});
  auto scan = http_post(
      "api/intelligence/smart-scan",
      {{"target", target}, {"objective", objective}, {"max_tools", max_tools}});
  log(Log::INFO, "✅ AI reconnaissance workflow completed for " + target);
  return {{"success", true},
          {"target", target},
          {"depth", depth},
          {"target_analysis", analysis.value("target_profile", json{})},
          {"attack_chain", chain.value("attack_chain", json{})},
          {"scan_results", scan.value("scan_results", json{})}};
}

json tool_ai_vulnerability_assessment(const json &a) {
  std::string target = a.value("target", ""),
              focus = a.value("focus_areas", "all");
  log(Log::INFO, "🔬 Starting AI vulnerability assessment for " + target);
  auto analysis =
      http_post("api/intelligence/analyze-target", {{"target", target}});
  if (!analysis.value("success", false))
    return analysis;
  auto prof = analysis.value("target_profile", json{});
  std::string objective = "comprehensive";
  auto scan = http_post(
      "api/intelligence/smart-scan",
      {{"target", target}, {"objective", objective}, {"max_tools", 6}});
  log(Log::INFO, "✅ AI vulnerability assessment completed");
  return {{"success", true},
          {"target", target},
          {"focus_areas", focus},
          {"target_analysis", prof},
          {"vulnerability_scan", scan.value("scan_results", json{})},
          {"risk_assessment",
           {{"risk_level", prof.value("risk_level", "?")},
            {"attack_surface_score", prof.value("attack_surface_score", 0.0)},
            {"confidence_score", prof.value("confidence_score", 0.0)}}}};
}

// ── BUG BOUNTY
// ────────────────────────────────────────────────────────────────
json tool_bugbounty_reconnaissance_workflow(const json &a) {
  log(Log::INFO,
      "🎯 Creating reconnaissance workflow for " + a.value("domain", ""));
  json scope_arr = json::array(), oos_arr = json::array();
  std::string sc = a.value("scope", "");
  std::istringstream s1(sc);
  std::string item;
  while (std::getline(s1, item, ',')) {
    item.erase(0, item.find_first_not_of(" "));
    if (!item.empty())
      scope_arr.push_back(item);
  }
  std::string oos = a.value("out_of_scope", "");
  std::istringstream s2(oos);
  while (std::getline(s2, item, ',')) {
    item.erase(0, item.find_first_not_of(" "));
    if (!item.empty())
      oos_arr.push_back(item);
  }
  json p;
  p["domain"] = a.value("domain", "");
  p["scope"] = scope_arr;
  p["out_of_scope"] = oos_arr;
  p["program_type"] = a.value("program_type", "web");
  auto r = http_post("api/bugbounty/reconnaissance-workflow", p);
  if (r.value("success", false)) {
    auto wf = r.value("workflow", json{});
    log(Log::INFO, "✅ Recon workflow created - " +
                       std::to_string(wf.value("tools_count", 0)) +
                       " tools, ~" +
                       std::to_string(wf.value("estimated_time", 0)) + "s");
  } else
    log(Log::ERROR, "❌ Failed to create recon workflow");
  return r;
}

json tool_bugbounty_vulnerability_hunting(const json &a) {
  log(Log::INFO, "🎯 Creating vulnerability hunting workflow for " +
                     a.value("domain", ""));
  json pv = json::array();
  std::string pvs = a.value("priority_vulns", "rce,sqli,xss,idor,ssrf");
  std::istringstream ss(pvs);
  std::string v;
  while (std::getline(ss, v, ',')) {
    v.erase(0, v.find_first_not_of(" "));
    if (!v.empty())
      pv.push_back(v);
  }
  json p;
  p["domain"] = a.value("domain", "");
  p["priority_vulns"] = pv;
  p["bounty_range"] = a.value("bounty_range", "unknown");
  auto r = http_post("api/bugbounty/vulnerability-hunting-workflow", p);
  if (r.value("success", false))
    log(Log::INFO,
        "✅ Vuln hunting workflow created - Priority score: " +
            std::to_string(
                r.value("workflow", json{}).value("priority_score", 0)));
  else
    log(Log::ERROR, "❌ Failed to create vuln hunting workflow");
  return r;
}

json tool_bugbounty_business_logic_testing(const json &a) {
  log(Log::INFO, "🎯 Creating business logic testing workflow for " +
                     a.value("domain", ""));
  json p;
  p["domain"] = a.value("domain", "");
  p["program_type"] = a.value("program_type", "web");
  auto r = http_post("api/bugbounty/business-logic-workflow", p);
  if (r.value("success", false)) {
    auto wf = r.value("workflow", json{});
    int tc = 0;
    for (auto &cat : wf.value("business_logic_tests", json::array()))
      tc += (int)cat.value("tests", json::array()).size();
    log(Log::INFO, "✅ Business logic workflow created - " +
                       std::to_string(tc) + " tests");
  } else
    log(Log::ERROR, "❌ Failed to create business logic workflow");
  return r;
}

json tool_bugbounty_osint_gathering(const json &a) {
  log(Log::INFO,
      "🎯 Creating OSINT gathering workflow for " + a.value("domain", ""));
  json p;
  p["domain"] = a.value("domain", "");
  auto r = http_post("api/bugbounty/osint-workflow", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ OSINT workflow created - " +
                       std::to_string((int)r.value("workflow", json{})
                                          .value("osint_phases", json::array())
                                          .size()) +
                       " phases");
  else
    log(Log::ERROR, "❌ Failed to create OSINT workflow");
  return r;
}

json tool_bugbounty_file_upload_testing(const json &a) {
  log(Log::INFO, "🎯 Creating file upload testing workflow for " +
                     a.value("target_url", ""));
  json p;
  p["target_url"] = a.value("target_url", "");
  auto r = http_post("api/bugbounty/file-upload-testing", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ File upload testing workflow created - " +
                       std::to_string((int)r.value("workflow", json{})
                                          .value("test_phases", json::array())
                                          .size()) +
                       " phases");
  else
    log(Log::ERROR, "❌ Failed to create file upload workflow");
  return r;
}

json tool_bugbounty_comprehensive_assessment(const json &a) {
  log(Log::INFO, "🎯 Creating comprehensive bug bounty assessment for " +
                     a.value("domain", ""));
  json pv = json::array();
  std::string pvs = a.value("priority_vulns", "rce,sqli,xss,idor,ssrf");
  std::istringstream ss(pvs);
  std::string v;
  while (std::getline(ss, v, ',')) {
    v.erase(0, v.find_first_not_of(" "));
    if (!v.empty())
      pv.push_back(v);
  }
  json p;
  p["domain"] = a.value("domain", "");
  p["priority_vulns"] = pv;
  p["include_osint"] = a.value("include_osint", true);
  p["include_business_logic"] = a.value("include_business_logic", true);
  auto r = http_post("api/bugbounty/comprehensive-assessment", p);
  if (r.value("success", false)) {
    auto summary = r.value("assessment", json{}).value("summary", json{});
    log(Log::INFO, "✅ Comprehensive assessment created - " +
                       std::to_string(summary.value("workflow_count", 0)) +
                       " workflows");
  } else
    log(Log::ERROR, "❌ Failed to create comprehensive assessment");
  return r;
}

json tool_bugbounty_authentication_bypass_testing(const json &a) {
  std::string target_url = a.value("target_url", ""),
              auth_type = a.value("auth_type", "form");
  log(Log::INFO,
      "🎯 Created authentication bypass testing workflow for " + target_url);
  // Return workflow directly (no server endpoint needed — same as Python impl)
  json bypass;
  json fa = json::array();
  if (auth_type == "form") {
    fa.push_back({{"technique", "SQL Injection"},
                  {"payloads", {"admin'--", "' OR '1'='1'--"}}});
    fa.push_back({{"technique", "Default Credentials"},
                  {"payloads", {"admin:admin", "admin:password"}}});
    fa.push_back(
        {{"technique", "Password Reset"},
         {"description", "Test password reset token reuse and manipulation"}});
    fa.push_back({{"technique", "Session Fixation"},
                  {"description", "Test session ID prediction and fixation"}});
  } else if (auth_type == "jwt") {
    fa.push_back({{"technique", "Algorithm Confusion"},
                  {"description", "Change RS256 to HS256"}});
    fa.push_back({{"technique", "None Algorithm"},
                  {"description", "Set algorithm to 'none'"}});
    fa.push_back({{"technique", "Key Confusion"},
                  {"description", "Use public key as HMAC secret"}});
  } else if (auth_type == "oauth") {
    fa.push_back({{"technique", "Redirect URI Manipulation"},
                  {"description", "Test open redirect in redirect_uri"}});
    fa.push_back(
        {{"technique", "State Parameter"},
         {"description", "Test CSRF via missing/weak state parameter"}});
    fa.push_back({{"technique", "Code Reuse"},
                  {"description", "Test authorization code reuse"}});
  } else {
    fa.push_back({{"technique", "XML Signature Wrapping"},
                  {"description", "Manipulate SAML assertions"}});
    fa.push_back({{"technique", "XML External Entity"},
                  {"description", "Test XXE in SAML requests"}});
  }
  json wf;
  wf["target"] = target_url;
  wf["auth_type"] = auth_type;
  wf["bypass_techniques"] = fa;
  wf["testing_phases"] = {
      {{"phase", "reconnaissance"},
       {"description", "Identify authentication mechanisms"}},
      {{"phase", "baseline_testing"},
       {"description", "Test normal authentication flow"}},
      {{"phase", "bypass_testing"}, {"description", "Apply bypass techniques"}},
      {{"phase", "privilege_escalation"},
       {"description", "Test for privilege escalation"}}};
  wf["estimated_time"] = 240;
  wf["manual_testing_required"] = true;
  return {{"success", true}, {"workflow", wf}};
}

// ── FILES / PAYLOADS
// ────────────────────────────────────────────────────────────
json tool_create_file(const json &a) {
  log(Log::INFO, "📄 Creating file: " + a.value("filename", ""));
  json p;
  p["filename"] = a.value("filename", "unnamed.txt");
  p["content"] = a.value("content", "");
  p["binary"] = a.value("binary", false);
  auto r = http_post("api/files/create", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ File created: " + a.value("filename", ""));
  else
    log(Log::ERROR, "❌ Failed to create file: " + a.value("filename", ""));
  return r;
}

json tool_modify_file(const json &a) {
  log(Log::INFO, "✏️  Modifying file: " + a.value("filename", ""));
  json p;
  p["filename"] = a.value("filename", "");
  p["content"] = a.value("content", "");
  p["append"] = a.value("append", false);
  auto r = http_post("api/files/modify", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ File modified: " + a.value("filename", ""));
  else
    log(Log::ERROR, "❌ Failed to modify file: " + a.value("filename", ""));
  return r;
}

json tool_delete_file(const json &a) {
  log(Log::INFO, "🗑️  Deleting file: " + a.value("filename", ""));
  json p;
  p["filename"] = a.value("filename", "");
  auto r = http_post("api/files/delete", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ File deleted: " + a.value("filename", ""));
  else
    log(Log::ERROR, "❌ Failed to delete file: " + a.value("filename", ""));
  return r;
}

json tool_list_files(const json &a) {
  log(Log::INFO, "📂 Listing files in directory: " + a.value("directory", "."));
  auto r =
      http_get("api/files/list", {{"directory", a.value("directory", ".")}});
  if (r.value("success", false))
    log(Log::INFO,
        "✅ Listed " +
            std::to_string((int)r.value("files", json::array()).size()) +
            " files");
  else
    log(Log::ERROR, "❌ Failed to list files");
  return r;
}

json tool_generate_payload(const json &a) {
  log(Log::INFO, "🎯 Generating " + a.value("payload_type", "buffer") +
                     " payload: " + std::to_string(a.value("size", 1024)) +
                     " bytes");
  json p;
  p["type"] = a.value("payload_type", "buffer");
  p["size"] = a.value("size", 1024);
  p["pattern"] = a.value("pattern", "A");
  std::string fn = a.value("filename", "");
  if (!fn.empty())
    p["filename"] = fn;
  auto r = http_post("api/payloads/generate", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Payload generated successfully");
  else
    log(Log::ERROR, "❌ Failed to generate payload");
  return r;
}

// ── PYTHON ENV
// ────────────────────────────────────────────────────────────────
json tool_install_python_package(const json &a) {
  log(Log::INFO, "📦 Installing Python package: " + a.value("package", "") +
                     " in env " + a.value("env_name", "default"));
  json p;
  p["package"] = a.value("package", "");
  p["env_name"] = a.value("env_name", "default");
  auto r = http_post("api/python/install", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Package " + a.value("package", "") + " installed");
  else
    log(Log::ERROR, "❌ Failed to install package " + a.value("package", ""));
  return r;
}

json tool_execute_python_script(const json &a) {
  log(Log::INFO,
      "🐍 Executing Python script in env " + a.value("env_name", "default"));
  json p;
  p["script"] = a.value("script", "");
  p["env_name"] = a.value("env_name", "default");
  std::string fn = a.value("filename", "");
  if (!fn.empty())
    p["filename"] = fn;
  auto r = http_post("api/python/execute", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Python script executed successfully");
  else
    log(Log::ERROR, "❌ Python script execution failed");
  return r;
}

// ── PROCESS MANAGEMENT
// ──────────────────────────────────────────────────────────
json tool_list_active_processes(const json &) {
  log(Log::INFO, "📊 Listing active processes");
  auto r = http_get("api/processes/list");
  if (r.value("success", false))
    log(Log::INFO, "✅ Found " + std::to_string(r.value("total_count", 0)) +
                       " active processes");
  else
    log(Log::ERROR, "❌ Failed to list processes");
  return r;
}

json tool_get_process_status(const json &a) {
  int pid = a.value("pid", 0);
  log(Log::INFO, "🔍 Checking status of process " + std::to_string(pid));
  auto r = http_get("api/processes/status/" + std::to_string(pid));
  if (r.value("success", false))
    log(Log::INFO, "✅ Process " + std::to_string(pid) + " status retrieved");
  else
    log(Log::ERROR, "❌ Process " + std::to_string(pid) + " not found");
  return r;
}

json tool_terminate_process(const json &a) {
  int pid = a.value("pid", 0);
  log(Log::INFO, "🛑 Terminating process " + std::to_string(pid));
  auto r = http_post("api/processes/terminate/" + std::to_string(pid), {});
  if (r.value("success", false))
    log(Log::INFO, "✅ Process " + std::to_string(pid) + " terminated");
  else
    log(Log::ERROR, "❌ Failed to terminate process " + std::to_string(pid));
  return r;
}

json tool_pause_process(const json &a) {
  int pid = a.value("pid", 0);
  log(Log::INFO, "⏸️ Pausing process " + std::to_string(pid));
  auto r = http_post("api/processes/pause/" + std::to_string(pid), {});
  if (r.value("success", false))
    log(Log::INFO, "✅ Process " + std::to_string(pid) + " paused");
  else
    log(Log::ERROR, "❌ Failed to pause process " + std::to_string(pid));
  return r;
}

json tool_resume_process(const json &a) {
  int pid = a.value("pid", 0);
  log(Log::INFO, "▶️ Resuming process " + std::to_string(pid));
  auto r = http_post("api/processes/resume/" + std::to_string(pid), {});
  if (r.value("success", false))
    log(Log::INFO, "✅ Process " + std::to_string(pid) + " resumed");
  else
    log(Log::ERROR, "❌ Failed to resume process " + std::to_string(pid));
  return r;
}

json tool_get_process_dashboard(const json &) {
  log(Log::INFO, "📊 Getting process dashboard");
  auto r = http_get("api/processes/dashboard");
  if (r.value("total_processes", -1) >= 0) {
    int total = r.value("total_processes", 0);
    log(Log::INFO, "✅ Dashboard retrieved: " + std::to_string(total) +
                       " active processes");
    if (total > 0) {
      log(Log::INFO, "📈 Active Processes Summary:");
      for (auto &proc : r.value("processes", json::array())) {
        log(Log::INFO, "   ├─ PID " + std::to_string(proc.value("pid", 0)) +
                           ": " + proc.value("progress_bar", "") +
                           proc.value("progress_percent", ""));
      }
    }
  } else
    log(Log::ERROR, "❌ Failed to get process dashboard");
  return r;
}

json tool_execute_command(const json &a) {
  log(Log::INFO, "⚡ Executing command: " + a.value("command", ""));
  json p;
  p["command"] = a.value("command", "");
  p["use_cache"] = a.value("use_cache", true);
  auto r = http_post("api/command", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Command completed in " +
                       std::to_string(r.value("execution_time", 0.0)) + "s");
  else
    log(Log::WARNING, "⚠️  Command completed with errors");
  return r;
}

// ── MONITORING / TELEMETRY
// ────────────────────────────────────────────────────
json tool_server_health(const json &) {
  log(Log::INFO, "🏥 Checking mantra AI server health");
  auto r = http_get("health");
  if (r.value("status", "") == "healthy")
    log(Log::INFO, "✅ Server is healthy - " +
                       std::to_string(r.value("total_tools_available", 0)) +
                       " tools available");
  else
    log(Log::WARNING,
        "⚠️  Server health check returned: " + r.value("status", "unknown"));
  return r;
}

json tool_get_cache_stats(const json &) {
  log(Log::INFO, "💾 Getting cache statistics");
  auto r = http_get("api/cache/stats");
  if (r.contains("hit_rate"))
    log(Log::INFO, "📊 Cache hit rate: " + r.value("hit_rate", "unknown"));
  return r;
}

json tool_clear_cache(const json &) {
  log(Log::INFO, "🧹 Clearing server cache");
  auto r = http_post("api/cache/clear", {});
  if (r.value("success", false))
    log(Log::INFO, "✅ Cache cleared successfully");
  else
    log(Log::ERROR, "❌ Failed to clear cache");
  return r;
}

json tool_get_telemetry(const json &) {
  log(Log::INFO, "📈 Getting system telemetry");
  auto r = http_get("api/telemetry");
  if (r.contains("commands_executed"))
    log(Log::INFO, "📊 Commands executed: " +
                       std::to_string(r.value("commands_executed", 0)));
  return r;
}

// ── VISUAL OUTPUT TOOLS
// ────────────────────────────────────────────────────────
json tool_get_live_dashboard(const json &) {
  log(Log::INFO, "📊 Fetching live process dashboard");
  auto r = http_get("api/processes/dashboard");
  if (r.value("success", true))
    log(Log::INFO, "✅ Live dashboard retrieved");
  else
    log(Log::ERROR, "❌ Failed to retrieve live dashboard");
  return r;
}

json tool_create_vulnerability_report(const json &a) {
  std::string vulns_str = a.value("vulnerabilities", "[]");
  std::string target = a.value("target", ""),
              scan_type = a.value("scan_type", "comprehensive");
  try {
    json vuln_data = json::parse(vulns_str);
    log(Log::INFO, "📋 Creating vulnerability report for " +
                       std::to_string((int)vuln_data.size()) + " findings");
    json cards = json::array();
    for (auto &v : vuln_data) {
      auto cr = http_post("api/visual/vulnerability-card", v);
      if (cr.value("success", false))
        cards.push_back(cr.value("vulnerability_card", ""));
    }
    auto summary_r =
        http_post("api/visual/summary-report", {{"target", target},
                                                {"vulnerabilities", vuln_data},
                                                {"tools_used", {scan_type}},
                                                {"execution_time", 0}});
    log(Log::INFO, "✅ Vulnerability report created");
    return {{"success", true},
            {"vulnerability_cards", cards},
            {"summary_report", summary_r.value("summary_report", "")},
            {"total_vulnerabilities", (int)vuln_data.size()},
            {"timestamp", summary_r.value("timestamp", "")}};
  } catch (const std::exception &e) {
    log(Log::ERROR,
        "❌ Failed to create vulnerability report: " + std::string(e.what()));
    return {{"success", false}, {"error", e.what()}};
  }
}

json tool_format_tool_output_visual(const json &a) {
  log(Log::INFO, "🎨 Formatting output for " + a.value("tool_name", ""));
  json p;
  p["tool"] = a.value("tool_name", "");
  p["output"] = a.value("output", "");
  p["success"] = a.value("success", true);
  auto r = http_post("api/visual/tool-output", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Tool output formatted");
  else
    log(Log::ERROR, "❌ Failed to format tool output");
  return r;
}

json tool_create_scan_summary(const json &a) {
  log(Log::INFO, "📊 Creating scan summary for " + a.value("target", ""));
  std::string tools_str = a.value("tools_used", "");
  json tl = json::array();
  std::istringstream ss(tools_str);
  std::string t;
  while (std::getline(ss, t, ',')) {
    t.erase(0, t.find_first_not_of(" "));
    if (!t.empty())
      tl.push_back(t);
  }
  int n = a.value("vulnerabilities_found", 0);
  json vl = json::array();
  for (int i = 0; i < n; ++i)
    vl.push_back({{"severity", "info"}});
  json p;
  p["target"] = a.value("target", "");
  p["tools_used"] = tl;
  p["execution_time"] = a.value("execution_time", 0.0);
  p["vulnerabilities"] = vl;
  auto r = http_post("api/visual/summary-report", p);
  if (r.value("success", false))
    log(Log::INFO, "✅ Scan summary created");
  else
    log(Log::ERROR, "❌ Failed to create scan summary");
  return r;
}

json tool_display_system_metrics(const json &) {
  log(Log::INFO, "📈 Fetching system metrics");
  auto r = http_get("api/telemetry");
  if (r.value("success", true)) {
    auto m = r.value("system_metrics", json{});
    json stats;
    stats["cpu_percent"] = m.value("cpu_percent", 0.0);
    stats["memory_percent"] = m.value("memory_percent", 0.0);
    stats["disk_usage"] = m.value("disk_usage", 0.0);
    stats["uptime_seconds"] = r.value("uptime_seconds", 0);
    stats["commands_executed"] = r.value("commands_executed", 0);
    stats["success_rate"] = r.value("success_rate", "0%");
    log(Log::INFO, "✅ System metrics retrieved");
    return {{"success", true},
            {"metrics", stats},
            {"timestamp", r.value("timestamp", "")}};
  }
  return r;
}

// ── ERROR HANDLING
// ─────────────────────────────────────────────────────────────
json tool_error_handling_statistics(const json &) {
  log(Log::INFO, std::string(Col::ELECTRIC_PURPLE) +
                     "📊 Retrieving error handling statistics" + Col::RESET);
  auto r = http_get("api/error-handling/statistics");
  if (r.value("success", false)) {
    auto stats = r.value("statistics", json{});
    log(Log::INFO, std::string(Col::SUCCESS) + "✅ Error statistics retrieved" +
                       Col::RESET);
    log(Log::INFO,
        "  📈 Total Errors: " + std::to_string(stats.value("total_errors", 0)));
    auto ects = stats.value("error_counts_by_type", json{});
    if (!ects.empty()) {
      log(Log::INFO,
          std::string(Col::HL_BLUE) + " ERROR BREAKDOWN " + Col::RESET);
      for (auto &[k, v] : ects.items())
        log(Log::INFO, "  " + std::string(Col::FIRE_RED) + k + ": " +
                           std::to_string(v.get<int>()) + Col::RESET);
    }
  } else
    log(Log::ERROR, std::string(Col::ERR) +
                        "❌ Failed to retrieve error statistics" + Col::RESET);
  return r;
}

json tool_test_error_recovery(const json &a) {
  log(Log::INFO, std::string(Col::RUBY) + "🧪 Testing error recovery for " +
                     a.value("tool_name", "nmap") + " with " +
                     a.value("error_type", "timeout") + Col::RESET);
  json p;
  p["tool_name"] = a.value("tool_name", "nmap");
  p["error_type"] = a.value("error_type", "timeout");
  p["target"] = a.value("target", "example.com");
  auto r = http_post("api/error-handling/test-recovery", p);
  if (r.value("success", false)) {
    auto strat = r.value("recovery_strategy", json{});
    log(Log::INFO, std::string(Col::SUCCESS) +
                       "✅ Error recovery test completed" + Col::RESET);
    log(Log::INFO, "  🔧 Recovery Action: " + strat.value("action", "?"));
    log(Log::INFO, "  📊 Success Probability: " +
                       std::to_string(strat.value("success_probability", 0.0)));
    auto alts = r.value("alternative_tools", json::array());
    if (!alts.empty()) {
      std::string as;
      for (auto &a : alts) {
        if (!as.empty())
          as += ",";
        as += a.get<std::string>();
      }
      log(Log::INFO, "  🔄 Alternative Tools: " + as);
    }
  } else
    log(Log::ERROR,
        std::string(Col::ERR) + "❌ Error recovery test failed" + Col::RESET);
  return r;
}

// ── API SECURITY
// ──────────────────────────────────────────────────────────────
json tool_graphql_scanner(const json &a) {
  log(Log::INFO,
      "🔍 Starting GraphQL security scan: " + a.value("endpoint", ""));
  json p;
  p["endpoint"] = a.value("endpoint", "");
  p["introspection"] = a.value("introspection", true);
  p["query_depth"] = a.value("query_depth", 10);
  p["test_mutations"] = a.value("test_mutations", true);
  auto r = http_post("api/tools/graphql_scanner", p);
  if (r.value("success", false)) {
    auto sr = r.value("graphql_scan_results", json{});
    int vc = (int)sr.value("vulnerabilities", json::array()).size();
    int tc = (int)sr.value("tests_performed", json::array()).size();
    log(Log::INFO, "✅ GraphQL scan completed: " + std::to_string(tc) +
                       " tests, " + std::to_string(vc) + " vulnerabilities");
    if (vc > 0) {
      log(Log::WARNING,
          "⚠️  Found " + std::to_string(vc) + " GraphQL vulnerabilities!");
      for (auto &v : sr.value("vulnerabilities", json::array()))
        log(Log::WARNING,
            "   ├─ [" + v.value("severity", "?") + "] " + v.value("type", "?"));
    }
  } else
    log(Log::ERROR, "❌ GraphQL scanning failed");
  return r;
}

json tool_jwt_analyzer(const json &a) {
  log(Log::INFO, "🔍 Starting JWT security analysis");
  json p;
  p["jwt_token"] = a.value("jwt_token", "");
  p["target_url"] = a.value("target_url", "");
  auto r = http_post("api/tools/jwt_analyzer", p);
  if (r.value("success", false)) {
    auto analysis = r.value("jwt_analysis_results", json{});
    int vc = (int)analysis.value("vulnerabilities", json::array()).size();
    std::string alg =
        analysis.value("token_info", json{}).value("algorithm", "unknown");
    log(Log::INFO, "✅ JWT analysis completed: " + std::to_string(vc) +
                       " vulnerabilities | Algorithm: " + alg);
    if (vc > 0) {
      log(Log::WARNING,
          "⚠️  Found " + std::to_string(vc) + " JWT vulnerabilities!");
      for (auto &v : analysis.value("vulnerabilities", json::array()))
        log(Log::WARNING,
            "   ├─ [" + v.value("severity", "?") + "] " + v.value("type", "?"));
    }
  } else
    log(Log::ERROR, "❌ JWT analysis failed");
  return r;
}

json tool_api_fuzzer(const json &a) {
  log(Log::INFO, "🔍 Starting API fuzzing: " + a.value("base_url", ""));
  std::string eps_str = a.value("endpoints", "");
  json eps = json::array();
  if (!eps_str.empty()) {
    std::istringstream ss(eps_str);
    std::string e;
    while (std::getline(ss, e, ',')) {
      e.erase(0, e.find_first_not_of(" "));
      if (!e.empty())
        eps.push_back(e);
    }
  }
  std::string mts_str = a.value("methods", "GET,POST,PUT,DELETE");
  json mts = json::array();
  {
    std::istringstream ss(mts_str);
    std::string m;
    while (std::getline(ss, m, ',')) {
      m.erase(0, m.find_first_not_of(" "));
      if (!m.empty())
        mts.push_back(m);
    }
  }
  json p;
  p["base_url"] = a.value("base_url", "");
  p["endpoints"] = eps;
  p["methods"] = mts;
  p["wordlist"] =
      a.value("wordlist", "/usr/share/wordlists/api/api-endpoints.txt");
  auto r = http_post("api/tools/api_fuzzer", p);
  if (r.value("success", false)) {
    std::string ft = r.value("fuzzing_type", "unknown");
    if (ft == "endpoint_testing")
      log(Log::INFO,
          "✅ API endpoint testing completed: " +
              std::to_string((int)r.value("results", json::array()).size()) +
              " endpoints");
    else
      log(Log::INFO, "✅ API endpoint discovery completed");
  } else
    log(Log::ERROR, "❌ API fuzzing failed");
  return r;
}

json tool_api_schema_analyzer(const json &a) {
  log(Log::INFO,
      "🔍 Starting API schema analysis: " + a.value("schema_url", ""));
  json p;
  p["schema_url"] = a.value("schema_url", "");
  p["schema_type"] = a.value("schema_type", "openapi");
  auto r = http_post("api/tools/api_schema_analyzer", p);
  if (r.value("success", false)) {
    auto analysis = r.value("schema_analysis_results", json{});
    int ec = (int)analysis.value("endpoints_found", json::array()).size();
    int ic = (int)analysis.value("security_issues", json::array()).size();
    log(Log::INFO, "✅ Schema analysis completed: " + std::to_string(ec) +
                       " endpoints, " + std::to_string(ic) + " issues");
    if (ic > 0) {
      log(Log::WARNING,
          "⚠️  Found " + std::to_string(ic) + " security issues in schema!");
      for (auto &issue : analysis.value("security_issues", json::array()))
        log(Log::WARNING, "   ├─ [" + issue.value("severity", "?") + "] " +
                              issue.value("issue", "?"));
    }
  } else
    log(Log::ERROR, "❌ Schema analysis failed");
  return r;
}

json tool_comprehensive_api_audit(const json &a) {
  std::string base_url = a.value("base_url", "");
  std::string schema_url = a.value("schema_url", ""),
              jwt_token = a.value("jwt_token", ""),
              graphql_ep = a.value("graphql_endpoint", "");
  log(Log::INFO, "🚀 Starting comprehensive API security audit: " + base_url);
  json audit;
  audit["base_url"] = base_url;
  audit["tests_performed"] = json::array();
  audit["total_vulnerabilities"] = 0;

  log(Log::INFO, "🔍 Phase 1: API endpoint discovery and fuzzing");
  auto fuzz =
      http_post("api/tools/api_fuzzer",
                {{"base_url", base_url},
                 {"endpoints", json::array()},
                 {"methods", json::array({"GET", "POST", "PUT", "DELETE"})},
                 {"wordlist", "/usr/share/wordlists/dirb/common.txt"}});
  if (fuzz.value("success", false)) {
    audit["tests_performed"].push_back("api_fuzzing");
    audit["api_fuzzing"] = fuzz;
  }

  if (!schema_url.empty()) {
    log(Log::INFO, "🔍 Phase 2: API schema analysis");
    auto schema =
        http_post("api/tools/api_schema_analyzer",
                  {{"schema_url", schema_url}, {"schema_type", "openapi"}});
    if (schema.value("success", false)) {
      audit["tests_performed"].push_back("schema_analysis");
      audit["schema_analysis"] = schema;
      audit["total_vulnerabilities"] =
          audit["total_vulnerabilities"].get<int>() +
          (int)schema.value("schema_analysis_results", json{})
              .value("security_issues", json::array())
              .size();
    }
  }
  if (!jwt_token.empty()) {
    log(Log::INFO, "🔍 Phase 3: JWT token analysis");
    auto jwt = http_post("api/tools/jwt_analyzer",
                         {{"jwt_token", jwt_token}, {"target_url", base_url}});
    if (jwt.value("success", false)) {
      audit["tests_performed"].push_back("jwt_analysis");
      audit["jwt_analysis"] = jwt;
      audit["total_vulnerabilities"] =
          audit["total_vulnerabilities"].get<int>() +
          (int)jwt.value("jwt_analysis_results", json{})
              .value("vulnerabilities", json::array())
              .size();
    }
  }
  if (!graphql_ep.empty()) {
    log(Log::INFO, "🔍 Phase 4: GraphQL security scanning");
    auto graphql =
        http_post("api/tools/graphql_scanner", {{"endpoint", graphql_ep},
                                                {"introspection", true},
                                                {"test_mutations", true}});
    if (graphql.value("success", false)) {
      audit["tests_performed"].push_back("graphql_scanning");
      audit["graphql_scanning"] = graphql;
      audit["total_vulnerabilities"] =
          audit["total_vulnerabilities"].get<int>() +
          (int)graphql.value("graphql_scan_results", json{})
              .value("vulnerabilities", json::array())
              .size();
    }
  }
  audit["recommendations"] = {
      "Implement proper authentication and authorization",
      "Use HTTPS for all API communications",
      "Validate and sanitize all input parameters", "Implement rate limiting",
      "Add comprehensive logging and monitoring"};
  audit["summary"] = {
      {"tests_performed", (int)audit["tests_performed"].size()},
      {"total_vulnerabilities", audit["total_vulnerabilities"]},
      {"audit_coverage", (int)audit["tests_performed"].size() >= 3
                             ? "comprehensive"
                             : "partial"}};
  log(Log::INFO,
      "✅ Comprehensive API audit completed: " +
          std::to_string(audit["summary"]["tests_performed"].get<int>()) +
          " tests, " +
          std::to_string(audit["total_vulnerabilities"].get<int>()) +
          " vulnerabilities");
  return {{"success", true}, {"comprehensive_audit", audit}};
}

// ── HTTP FRAMEWORK HELPERS (matching Python http_set_rules, http_repeater,
// etc.) ──
json tool_http_set_rules(const json &a) {
  json p;
  p["action"] = "set_rules";
  p["rules"] = a.value("rules", json::array());
  return http_post("api/tools/http-framework", p);
}
json tool_http_set_scope(const json &a) {
  json p;
  p["action"] = "set_scope";
  p["host"] = a.value("host", "");
  p["include_subdomains"] = a.value("include_subdomains", true);
  return http_post("api/tools/http-framework", p);
}
json tool_http_repeater(const json &a) {
  json p;
  p["action"] = "repeater";
  p["request"] = a.value("request_spec", json::object());
  return http_post("api/tools/http-framework", p);
}
json tool_http_intruder(const json &a) {
  json p;
  p["action"] = "intruder";
  p["url"] = a.value("url", "");
  p["method"] = a.value("method", "GET");
  p["location"] = a.value("location", "query");
  p["params"] = a.value("params", json::array());
  p["payloads"] = a.value("payloads", json::array());
  p["max_requests"] = a.value("max_requests", 100);
  return http_post("api/tools/http-framework", p);
}

// ============================================================================
// Tool dispatch table — every Python @mcp.tool() function mapped here
// ============================================================================
using ToolFn = std::function<json(const json &)>;
static const std::map<std::string, ToolFn> TOOL_DISPATCH = {
    // Network scanning
    {"nmap_scan", tool_nmap_scan},
    {"nmap_advanced_scan", tool_nmap_advanced_scan},
    {"rustscan_fast_scan", tool_rustscan_fast_scan},
    {"masscan_high_speed", tool_masscan_high_speed},
    {"autorecon_comprehensive", tool_autorecon_comprehensive},
    {"autorecon_scan", tool_autorecon_comprehensive},
    {"arp_scan_discovery", tool_arp_scan_discovery},
    {"nbtscan_netbios", tool_nbtscan_netbios},
    // Web scanning
    {"gobuster_scan", tool_gobuster_scan},
    {"nuclei_scan", tool_nuclei_scan},
    {"dirb_scan", tool_dirb_scan},
    {"nikto_scan", tool_nikto_scan},
    {"sqlmap_scan", tool_sqlmap_scan},
    {"wpscan_analyze", tool_wpscan_analyze},
    {"ffuf_scan", tool_ffuf_scan},
    {"feroxbuster_scan", tool_feroxbuster_scan},
    {"dirsearch_scan", tool_dirsearch_scan},
    {"dalfox_xss_scan", tool_dalfox_xss_scan},
    {"xsser_scan", tool_xsser_scan},
    {"wfuzz_scan", tool_wfuzz_scan},
    {"dotdotpwn_scan", tool_dotdotpwn_scan},
    {"wafw00f_scan", tool_wafw00f_scan},
    {"jaeles_vulnerability_scan", tool_jaeles_vulnerability_scan},
    {"burpsuite_scan", tool_burpsuite_scan},
    {"zap_scan", tool_zap_scan},
    // Recon / OSINT
    {"amass_scan", tool_amass_scan},
    {"subfinder_scan", tool_subfinder_scan},
    {"katana_crawl", tool_katana_crawl},
    {"gau_discovery", tool_gau_discovery},
    {"waybackurls_discovery", tool_waybackurls_discovery},
    {"hakrawler_crawl", tool_hakrawler_crawl},
    {"httpx_probe", tool_httpx_probe},
    {"arjun_parameter_discovery", tool_arjun_parameter_discovery},
    {"arjun_scan", tool_arjun_parameter_discovery},
    {"paramspider_mining", tool_paramspider_mining},
    {"paramspider_discovery", tool_paramspider_mining},
    {"x8_parameter_discovery", tool_x8_parameter_discovery},
    {"fierce_scan", tool_fierce_scan},
    {"dnsenum_scan", tool_dnsenum_scan},
    {"anew_data_processing", tool_anew_data_processing},
    {"qsreplace_parameter_replacement", tool_qsreplace_parameter_replacement},
    {"uro_url_filtering", tool_uro_url_filtering},
    // SMB / Windows
    {"enum4linux_scan", tool_enum4linux_scan},
    {"enum4linux_ng_advanced", tool_enum4linux_ng_advanced},
    {"smbmap_scan", tool_smbmap_scan},
    {"rpcclient_enumeration", tool_rpcclient_enumeration},
    {"netexec_scan", tool_netexec_scan},
    {"responder_credential_harvest", tool_responder_credential_harvest},
    // Credentials
    {"hydra_attack", tool_hydra_attack},
    {"john_crack", tool_john_crack},
    {"hashcat_crack", tool_hashcat_crack},
    {"hashpump_attack", tool_hashpump_attack},
    // Exploitation
    {"metasploit_run", tool_metasploit_run},
    {"msfvenom_generate", tool_msfvenom_generate},
    // Binary analysis
    {"gdb_analyze", tool_gdb_analyze},
    {"gdb_peda_debug", tool_gdb_peda_debug},
    {"radare2_analyze", tool_radare2_analyze},
    {"ghidra_analysis", tool_ghidra_analysis},
    {"binwalk_analyze", tool_binwalk_analyze},
    {"checksec_analyze", tool_checksec_analyze},
    {"strings_extract", tool_strings_extract},
    {"xxd_hexdump", tool_xxd_hexdump},
    {"objdump_analyze", tool_objdump_analyze},
    {"ropgadget_search", tool_ropgadget_search},
    {"ropper_gadget_search", tool_ropper_gadget_search},
    {"one_gadget_search", tool_one_gadget_search},
    {"pwntools_exploit", tool_pwntools_exploit},
    {"angr_symbolic_execution", tool_angr_symbolic_execution},
    {"pwninit_setup", tool_pwninit_setup},
    {"libc_database_lookup", tool_libc_database_lookup},
    // Forensics / stego
    {"volatility_analyze", tool_volatility_analyze},
    {"volatility3_analyze", tool_volatility3_analyze},
    {"foremost_carving", tool_foremost_carving},
    {"steghide_analysis", tool_steghide_analysis},
    {"exiftool_extract", tool_exiftool_extract},
    // Cloud / containers
    {"prowler_scan", tool_prowler_scan},
    {"trivy_scan", tool_trivy_scan},
    {"scout_suite_assessment", tool_scout_suite_assessment},
    {"cloudmapper_analysis", tool_cloudmapper_analysis},
    {"pacu_exploitation", tool_pacu_exploitation},
    {"kube_hunter_scan", tool_kube_hunter_scan},
    {"kube_bench_cis", tool_kube_bench_cis},
    {"docker_bench_security_scan", tool_docker_bench_security_scan},
    {"clair_vulnerability_scan", tool_clair_vulnerability_scan},
    {"falco_runtime_monitoring", tool_falco_runtime_monitoring},
    {"checkov_iac_scan", tool_checkov_iac_scan},
    {"terrascan_iac_scan", tool_terrascan_iac_scan},
    // HTTP framework / browser
    {"http_framework_test", tool_http_framework_test},
    {"browser_agent_inspect", tool_browser_agent_inspect},
    {"burpsuite_alternative_scan", tool_burpsuite_alternative_scan},
    {"http_set_rules", tool_http_set_rules},
    {"http_set_scope", tool_http_set_scope},
    {"http_repeater", tool_http_repeater},
    {"http_intruder", tool_http_intruder},
    // AI payloads
    {"ai_generate_payload", tool_ai_generate_payload},
    {"ai_test_payload", tool_ai_test_payload},
    {"ai_generate_attack_suite", tool_ai_generate_attack_suite},
    {"advanced_payload_generation", tool_advanced_payload_generation},
    // CVE intelligence
    {"monitor_cve_feeds", tool_monitor_cve_feeds},
    {"generate_exploit_from_cve", tool_generate_exploit_from_cve},
    {"discover_attack_chains", tool_discover_attack_chains},
    {"research_zero_day_opportunities", tool_research_zero_day_opportunities},
    {"correlate_threat_intelligence", tool_correlate_threat_intelligence},
    {"vulnerability_intelligence_dashboard",
     tool_vulnerability_intelligence_dashboard},
    {"threat_hunting_assistant", tool_threat_hunting_assistant},
    // Intelligence engine
    {"analyze_target_intelligence", tool_analyze_target_intelligence},
    {"select_optimal_tools_ai", tool_select_optimal_tools_ai},
    {"optimize_tool_parameters_ai", tool_optimize_tool_parameters_ai},
    {"create_attack_chain_ai", tool_create_attack_chain_ai},
    {"intelligent_smart_scan", tool_intelligent_smart_scan},
    {"detect_technologies_ai", tool_detect_technologies_ai},
    {"ai_reconnaissance_workflow", tool_ai_reconnaissance_workflow},
    {"ai_vulnerability_assessment", tool_ai_vulnerability_assessment},
    // Bug bounty
    {"bugbounty_reconnaissance_workflow",
     tool_bugbounty_reconnaissance_workflow},
    {"bugbounty_vulnerability_hunting", tool_bugbounty_vulnerability_hunting},
    {"bugbounty_business_logic_testing", tool_bugbounty_business_logic_testing},
    {"bugbounty_osint_gathering", tool_bugbounty_osint_gathering},
    {"bugbounty_file_upload_testing", tool_bugbounty_file_upload_testing},
    {"bugbounty_comprehensive_assessment",
     tool_bugbounty_comprehensive_assessment},
    {"bugbounty_authentication_bypass_testing",
     tool_bugbounty_authentication_bypass_testing},
    // Files / payloads
    {"create_file", tool_create_file},
    {"modify_file", tool_modify_file},
    {"delete_file", tool_delete_file},
    {"list_files", tool_list_files},
    {"generate_payload", tool_generate_payload},
    // Python env
    {"install_python_package", tool_install_python_package},
    {"execute_python_script", tool_execute_python_script},
    // Process management
    {"list_active_processes", tool_list_active_processes},
    {"get_process_status", tool_get_process_status},
    {"terminate_process", tool_terminate_process},
    {"pause_process", tool_pause_process},
    {"resume_process", tool_resume_process},
    {"get_process_dashboard", tool_get_process_dashboard},
    {"execute_command", tool_execute_command},
    // Monitoring
    {"server_health", tool_server_health},
    {"get_cache_stats", tool_get_cache_stats},
    {"clear_cache", tool_clear_cache},
    {"get_telemetry", tool_get_telemetry},
    // Visual output
    {"get_live_dashboard", tool_get_live_dashboard},
    {"create_vulnerability_report", tool_create_vulnerability_report},
    {"format_tool_output_visual", tool_format_tool_output_visual},
    {"create_scan_summary", tool_create_scan_summary},
    {"display_system_metrics", tool_display_system_metrics},
    // Error handling
    {"error_handling_statistics", tool_error_handling_statistics},
    {"test_error_recovery", tool_test_error_recovery},
    // API security
    {"graphql_scanner", tool_graphql_scanner},
    {"jwt_analyzer", tool_jwt_analyzer},
    {"api_fuzzer", tool_api_fuzzer},
    {"api_schema_analyzer", tool_api_schema_analyzer},
    {"comprehensive_api_audit", tool_comprehensive_api_audit},
};

// ============================================================================
// MCP tool definitions — inputSchema for every tool (for tools/list)
// ============================================================================
json build_tool_definitions() {
  json tools = json::array();

  auto add = [&](const std::string &name, const std::string &desc,
                 json schema) {
    tools.push_back(
        {{"name", name}, {"description", desc}, {"inputSchema", schema}});
  };

  auto S = [](std::initializer_list<std::pair<std::string, json>> props,
              std::vector<std::string> req = {}) -> json {
    json obj;
    obj["type"] = "object";
    obj["properties"] = json::object();
    for (auto &[k, v] : props)
      obj["properties"][k] = v;
    if (!req.empty()) {
      json ra = json::array();
      for (auto &r : req)
        ra.push_back(r);
      obj["required"] = ra;
    }
    return obj;
  };

  // String, int, bool, array shorthand
  auto Ss = [](const std::string &d, const std::string &def = "") -> json {
    json j = {{"type", "string"}, {"description", d}};
    if (!def.empty())
      j["default"] = def;
    return j;
  };
  auto Si = [](const std::string &d, int def = -999) -> json {
    json j = {{"type", "integer"}, {"description", d}};
    if (def != -999)
      j["default"] = def;
    return j;
  };
  auto Sb = [](const std::string &d, bool def = false) -> json {
    json j = {{"type", "boolean"}, {"description", d}, {"default", def}};
    return j;
  };
  auto Sa = [](const std::string &d) -> json {
    return json{
        {"type", "array"}, {"description", d}, {"items", {{"type", "string"}}}};
  };

  // ── Network Scanning ──
  add("nmap_scan", "Execute Nmap scan against a target",
      S({{"target", Ss("IP/hostname/CIDR")},
         {"scan_type", Ss("Scan type e.g. -sV -sC -sS", "-sV")},
         {"ports", Ss("Ports e.g. 80,443 or 1-1000", "")},
         {"additional_args", Ss("Extra nmap flags", "")},
         {"use_cache", Sb("Cache results", true)}},
        {"target"}));
  add("nmap_advanced_scan",
      "Execute advanced Nmap scan with NSE scripts and timing control",
      S({{"target", Ss("Target")},
         {"scan_type", Ss("Scan type", "-sS")},
         {"ports", Ss("Ports", "")},
         {"timing", Ss("Timing T0-T5", "T4")},
         {"nse_scripts", Ss("NSE script names", "")},
         {"os_detection", Sb("OS detection")},
         {"version_detection", Sb("Version detection")},
         {"aggressive", Sb("Aggressive scan")},
         {"stealth", Sb("Stealth mode")},
         {"additional_args", Ss("Extra flags", "")}},
        {"target"}));
  add("rustscan_fast_scan", "Ultra-fast port scanning with Rustscan",
      S({{"target", Ss("Target")},
         {"ports", Ss("Ports", "")},
         {"ulimit", Si("File descriptor limit", 5000)},
         {"batch_size", Si("Batch size", 4500)},
         {"timeout", Si("Timeout ms", 1500)},
         {"scripts", Sb("Run nmap scripts after")},
         {"additional_args", Ss("", "")}}));
  add("masscan_high_speed", "High-speed Internet-scale port scanning",
      S({{"target", Ss("Target IP or CIDR")},
         {"ports", Ss("Port range", "1-65535")},
         {"rate", Si("Packets per second", 1000)},
         {"interface", Ss("Network interface", "")},
         {"banners", Sb("Grab banners")},
         {"additional_args", Ss("", "")}}));
  add("autorecon_comprehensive",
      "Comprehensive automated reconnaissance (AutoRecon)",
      S({{"target", Ss("Target")},
         {"output_dir", Ss("Output directory", "/tmp/autorecon")},
         {"verbose", Si("Verbosity 0-3", 0)},
         {"additional_args", Ss("", "")}}));
  add("arp_scan_discovery", "ARP-based network host discovery",
      S({{"target", Ss("IP range", "")},
         {"interface", Ss("Network interface", "")},
         {"local_network", Sb("Scan local network")},
         {"timeout", Si("Timeout ms", 500)},
         {"retry", Si("Retries", 3)}}));
  add("nbtscan_netbios", "NetBIOS name scanning with nbtscan",
      S({{"target", Ss("Target IP or range")},
         {"verbose", Sb("Verbose")},
         {"timeout", Si("Timeout sec", 2)},
         {"additional_args", Ss("", "")}}));

  // ── Web Scanning ──
  add("gobuster_scan", "Directory/DNS/vhost brute forcing with Gobuster",
      S({{"url", Ss("Target URL")},
         {"mode", Ss("Mode: dir dns fuzz vhost", "dir")},
         {"wordlist",
          Ss("Wordlist path", "/usr/share/wordlists/dirb/common.txt")},
         {"additional_args", Ss("", "")}},
        {"url"}));
  add("nuclei_scan", "Nuclei vulnerability scanner with templates",
      S({{"target", Ss("Target URL or IP")},
         {"severity", Ss("Severity filter: critical,high,medium,low,info", "")},
         {"tags", Ss("Tag filter: cve,rce,lfi", "")},
         {"template", Ss("Custom template path", "")},
         {"additional_args", Ss("", "")}},
        {"target"}));
  add("dirb_scan", "Directory brute forcing with Dirb",
      S({{"url", Ss("Target URL")},
         {"wordlist", Ss("Wordlist", "/usr/share/wordlists/dirb/common.txt")},
         {"additional_args", Ss("", "")}},
        {"url"}));
  add("nikto_scan", "Web vulnerability scanner Nikto",
      S({{"target", Ss("Target URL or IP")}, {"additional_args", Ss("", "")}},
        {"target"}));
  add("sqlmap_scan", "SQL injection testing with SQLMap",
      S({{"url", Ss("Target URL")},
         {"data", Ss("POST data", "")},
         {"additional_args", Ss("", "")}},
        {"url"}));
  add("wpscan_analyze", "WordPress vulnerability scanning",
      S({{"url", Ss("WordPress site URL")}, {"additional_args", Ss("", "")}},
        {"url"}));
  add("ffuf_scan", "Web fuzzing with FFuf",
      S({{"url", Ss("Target URL")},
         {"wordlist", Ss("Wordlist", "/usr/share/wordlists/dirb/common.txt")},
         {"match_codes", Ss("HTTP codes", "200,204,301,302,307,401,403")},
         {"additional_args", Ss("", "")}},
        {"url"}));
  add("feroxbuster_scan", "Recursive content discovery with Feroxbuster",
      S({{"url", Ss("Target URL")},
         {"wordlist", Ss("Wordlist", "/usr/share/wordlists/dirb/common.txt")},
         {"threads", Si("Threads", 10)},
         {"additional_args", Ss("", "")}},
        {"url"}));
  add("dirsearch_scan", "Advanced directory/file discovery with Dirsearch",
      S({{"url", Ss("Target URL")},
         {"extensions", Ss("Extensions", "php,html,js,txt,xml,json")},
         {"threads", Si("Threads", 30)},
         {"recursive", Sb("Recursive")},
         {"wordlist", Ss("Wordlist", "")},
         {"additional_args", Ss("", "")}},
        {"url"}));
  add("dalfox_xss_scan", "Advanced XSS scanning with Dalfox",
      S({{"url", Ss("Target URL")},
         {"pipe_mode", Sb("Pipe mode")},
         {"blind", Sb("Blind XSS testing")},
         {"mining_dom", Sb("DOM mining", true)},
         {"mining_dict", Sb("Dict mining", true)},
         {"custom_payload", Ss("Custom payload", "")},
         {"additional_args", Ss("", "")}},
        {"url"}));
  add("xsser_scan", "XSS vulnerability testing with XSSer",
      S({{"url", Ss("Target URL")},
         {"params", Ss("Parameters to test", "")},
         {"additional_args", Ss("", "")}},
        {"url"}));
  add("wfuzz_scan", "Web application fuzzing with Wfuzz",
      S({{"url", Ss("Target URL with FUZZ placeholder")},
         {"wordlist", Ss("Wordlist", "/usr/share/wordlists/dirb/common.txt")},
         {"additional_args", Ss("", "")}},
        {"url"}));
  add("dotdotpwn_scan", "Directory traversal testing with DotDotPwn",
      S({{"target", Ss("Target hostname or IP")},
         {"module", Ss("Module: http ftp tftp", "http")},
         {"additional_args", Ss("", "")}},
        {"target"}));
  add("wafw00f_scan", "WAF detection and fingerprinting",
      S({{"target", Ss("Target URL or IP")}, {"additional_args", Ss("", "")}},
        {"target"}));
  add("jaeles_vulnerability_scan",
      "Advanced vulnerability scanning with Jaeles",
      S({{"url", Ss("Target URL")},
         {"signatures", Ss("Signature path", "")},
         {"threads", Si("Threads", 20)},
         {"timeout", Si("Timeout", 20)},
         {"additional_args", Ss("", "")}},
        {"url"}));
  add("burpsuite_scan", "Burp Suite web security scanner",
      S({{"project_file", Ss("Project file", "")},
         {"config_file", Ss("Config file", "")},
         {"target", Ss("Target URL", "")},
         {"headless", Sb("Headless mode")},
         {"additional_args", Ss("", "")}}));
  add("zap_scan", "OWASP ZAP vulnerability scanner",
      S({{"target", Ss("Target URL")},
         {"scan_type", Ss("Type: baseline full api", "baseline")},
         {"output_file", Ss("Output file", "")},
         {"additional_args", Ss("", "")}},
        {"target"}));
  add("burpsuite_alternative_scan",
      "Comprehensive Burp Suite alternative (katana+nuclei)",
      S({{"target", Ss("Target URL or domain")},
         {"scan_type",
          Ss("Type: comprehensive spider passive active", "comprehensive")},
         {"headless", Sb("Headless", true)},
         {"max_depth", Si("Max crawl depth", 3)},
         {"max_pages", Si("Max pages", 50)}},
        {"target"}));
  add("http_framework_test",
      "HTTP testing framework (request/spider/intruder/repeater)",
      S({{"url", Ss("Target URL")},
         {"method", Ss("HTTP method", "GET")},
         {"data", {{"type", "object"}, {"description", "Request data"}}},
         {"headers", {{"type", "object"}, {"description", "Custom headers"}}},
         {"cookies", {{"type", "object"}, {"description", "Cookies"}}},
         {"action",
          Ss("Action: request spider intruder repeater set_rules set_scope",
             "request")}},
        {"url"}));
  add("browser_agent_inspect",
      "AI-powered browser agent for web security analysis",
      S({{"url", Ss("Target URL")},
         {"headless", Sb("Headless", true)},
         {"wait_time", Si("Wait seconds", 5)},
         {"action", Ss("Action: navigate screenshot close", "navigate")},
         {"active_tests", Sb("Active XSS tests")}},
        {"url"}));

  // ── Recon / OSINT ──
  add("amass_scan", "Subdomain enumeration with Amass",
      S({{"domain", Ss("Target domain")},
         {"mode", Ss("Mode: enum intel viz", "enum")},
         {"additional_args", Ss("", "")}},
        {"domain"}));
  add("subfinder_scan", "Passive subdomain enumeration with Subfinder",
      S({{"domain", Ss("Target domain")},
         {"silent", Sb("Silent mode", true)},
         {"all_sources", Sb("Use all sources")},
         {"additional_args", Ss("", "")}},
        {"domain"}));
  add("katana_crawl", "Next-generation web crawling with Katana",
      S({{"url", Ss("Target URL")},
         {"depth", Si("Crawl depth", 3)},
         {"js_crawl", Sb("JS crawling", true)},
         {"form_extraction", Sb("Form extraction", true)},
         {"output_format", Ss("Format: json txt", "json")},
         {"additional_args", Ss("", "")}},
        {"url"}));
  add("gau_discovery", "URL discovery from Wayback, OTX, urlscan (Gau)",
      S({{"domain", Ss("Target domain")},
         {"providers", Ss("Providers", "wayback,commoncrawl,otx,urlscan")},
         {"include_subs", Sb("Include subdomains", true)},
         {"additional_args", Ss("", "")}},
        {"domain"}));
  add("waybackurls_discovery", "Historical URL discovery from Wayback Machine",
      S({{"domain", Ss("Target domain")},
         {"get_versions", Sb("Get all versions")},
         {"no_subs", Sb("Exclude subdomains")},
         {"additional_args", Ss("", "")}},
        {"domain"}));
  add("hakrawler_crawl", "Web endpoint discovery with Hakrawler",
      S({{"url", Ss("Target URL")},
         {"depth", Si("Crawl depth", 2)},
         {"forms", Sb("Include forms", true)},
         {"robots", Sb("Check robots.txt", true)},
         {"sitemap", Sb("Check sitemap", true)},
         {"wayback", Sb("Use Wayback")},
         {"additional_args", Ss("", "")}},
        {"url"}));
  add("httpx_probe", "Fast HTTP probing and technology detection",
      S({{"target", Ss("Target URL/file")},
         {"probe", Sb("Enable probing", true)},
         {"tech_detect", Sb("Technology detection")},
         {"status_code", Sb("Show status codes")},
         {"content_length", Sb("Show content length")},
         {"title", Sb("Show page titles")},
         {"web_server", Sb("Show web server")},
         {"threads", Si("Threads", 50)},
         {"additional_args", Ss("", "")}}));
  add("arjun_parameter_discovery", "HTTP parameter discovery with Arjun",
      S({{"url", Ss("Target URL")},
         {"method", Ss("HTTP method", "GET")},
         {"wordlist", Ss("Custom wordlist", "")},
         {"threads", Si("Threads", 25)},
         {"additional_args", Ss("", "")}},
        {"url"}));
  add("paramspider_mining", "Parameter mining from web archives (ParamSpider)",
      S({{"domain", Ss("Target domain")},
         {"level", Si("Mining level", 2)},
         {"exclude", Ss("Exclude extensions", "png,jpg,gif,jpeg")},
         {"output", Ss("Output file", "")},
         {"additional_args", Ss("", "")}},
        {"domain"}));
  add("x8_parameter_discovery", "Hidden parameter discovery with x8",
      S({{"url", Ss("Target URL")},
         {"wordlist", Ss("Wordlist", "")},
         {"method", Ss("HTTP method", "GET")},
         {"body", Ss("Request body", "")},
         {"headers", Ss("Custom headers", "")},
         {"additional_args", Ss("", "")}},
        {"url"}));
  add("fierce_scan", "DNS reconnaissance with Fierce",
      S({{"domain", Ss("Target domain")},
         {"dns_server", Ss("DNS server", "")},
         {"additional_args", Ss("", "")}},
        {"domain"}));
  add("dnsenum_scan", "DNS enumeration with dnsenum",
      S({{"domain", Ss("Target domain")},
         {"dns_server", Ss("DNS server", "")},
         {"wordlist", Ss("Wordlist for brute force", "")},
         {"additional_args", Ss("", "")}},
        {"domain"}));
  add("anew_data_processing", "Append new unique lines to a file (anew)",
      S({{"input_data", Ss("Input data")},
         {"output_file", Ss("Output file", "")},
         {"additional_args", Ss("", "")}}));
  add("qsreplace_parameter_replacement",
      "Query string parameter replacement (qsreplace)",
      S({{"urls", Ss("URLs to process")},
         {"replacement", Ss("Replacement string", "FUZZ")},
         {"additional_args", Ss("", "")}}));
  add("uro_url_filtering", "Filter out similar/duplicate URLs (uro)",
      S({{"urls", Ss("URLs to filter")},
         {"whitelist", Ss("Whitelist patterns", "")},
         {"blacklist", Ss("Blacklist patterns", "")},
         {"additional_args", Ss("", "")}}));

  // ── SMB / Windows ──
  add("enum4linux_scan", "SMB enumeration with Enum4linux",
      S({{"target", Ss("Target IP")}, {"additional_args", Ss("", "- a")}},
        {"target"}));
  add("enum4linux_ng_advanced", "Advanced SMB enumeration with Enum4linux-ng",
      S({{"target", Ss("Target IP")},
         {"username", Ss("Username", "")},
         {"password", Ss("Password", "")},
         {"domain", Ss("Domain", "")},
         {"shares", Sb("Enumerate shares", true)},
         {"users", Sb("Enumerate users", true)},
         {"groups", Sb("Enumerate groups", true)},
         {"policy", Sb("Enumerate policies", true)},
         {"additional_args", Ss("", "")}},
        {"target"}));
  add("smbmap_scan", "SMB share enumeration with SMBMap",
      S({{"target", Ss("Target IP")},
         {"username", Ss("Username", "")},
         {"password", Ss("Password", "")},
         {"domain", Ss("Domain", "")},
         {"additional_args", Ss("", "")}},
        {"target"}));
  add("rpcclient_enumeration", "RPC enumeration with rpcclient",
      S({{"target", Ss("Target IP")},
         {"username", Ss("Username", "")},
         {"password", Ss("Password", "")},
         {"domain", Ss("Domain", "")},
         {"commands", Ss("Semicolon-separated commands",
                         "enumdomusers;enumdomgroups;querydominfo")},
         {"additional_args", Ss("", "")}},
        {"target"}));
  add("netexec_scan",
      "Network enumeration with NetExec (formerly CrackMapExec)",
      S({{"target", Ss("Target IP or network")},
         {"protocol", Ss("Protocol: smb ssh winrm", "smb")},
         {"username", Ss("Username", "")},
         {"password", Ss("Password", "")},
         {"hash_value", Ss("NTLM hash", "")},
         {"module", Ss("Module", "")},
         {"additional_args", Ss("", "")}},
        {"target"}));
  add("responder_credential_harvest",
      "LLMNR/NBT-NS poisoning and credential harvesting",
      S({{"interface", Ss("Network interface", "eth0")},
         {"analyze", Sb("Analyze mode only")},
         {"wpad", Sb("Enable WPAD", true)},
         {"force_wpad_auth", Sb("Force WPAD auth")},
         {"fingerprint", Sb("Fingerprint mode")},
         {"duration", Si("Duration seconds", 300)},
         {"additional_args", Ss("", "")}}));

  // ── Credentials ──
  add("hydra_attack", "Password brute forcing with Hydra",
      S({{"target", Ss("Target IP/hostname")},
         {"service", Ss("Service: ssh ftp http smb", "ssh")},
         {"username", Ss("Single username", "")},
         {"username_file", Ss("Username file", "")},
         {"password", Ss("Single password", "")},
         {"password_file", Ss("Password file", "")},
         {"additional_args", Ss("", "")}},
        {"target", "service"}));
  add("john_crack", "Password cracking with John the Ripper",
      S({{"hash_file", Ss("File containing hashes")},
         {"wordlist", Ss("Wordlist", "/usr/share/wordlists/rockyou.txt")},
         {"format_type", Ss("Hash format e.g. md5 sha256", "")},
         {"additional_args", Ss("", "")}},
        {"hash_file"}));
  add("hashcat_crack", "Advanced password cracking with Hashcat",
      S({{"hash_file", Ss("File containing hashes")},
         {"hash_type", Ss("Hash type number e.g. 0=MD5 1000=NTLM")},
         {"attack_mode", Ss("Attack mode 0=dict 1=combo 3=mask", "0")},
         {"wordlist", Ss("Wordlist", "/usr/share/wordlists/rockyou.txt")},
         {"mask", Ss("Mask for mask attacks", "")},
         {"additional_args", Ss("", "")}},
        {"hash_file", "hash_type"}));
  add("hashpump_attack", "Hash length extension attacks with HashPump",
      S({{"signature", Ss("Original hash")},
         {"data", Ss("Original data")},
         {"key_length", Ss("Secret key length")},
         {"append_data", Ss("Data to append")},
         {"additional_args", Ss("", "")}},
        {"signature", "data", "key_length", "append_data"}));

  // ── Exploitation ──
  add("metasploit_run", "Execute a Metasploit module",
      S({{"module", Ss("Module path e.g. exploit/multi/handler")},
         {"options",
          {{"type", "object"},
           {"description", "Module options as key-value pairs"}}}},
        {"module"}));
  add("msfvenom_generate", "Generate payloads with MSFVenom",
      S({{"payload", Ss("Payload e.g. linux/x64/meterpreter/reverse_tcp")},
         {"format_type", Ss("Format: exe elf raw", "")},
         {"output_file", Ss("Output file", "")},
         {"encoder", Ss("Encoder", "")},
         {"iterations", Ss("Encoding iterations", "")},
         {"additional_args", Ss("", "")}},
        {"payload"}));

  // ── Binary Analysis ──
  add("gdb_analyze", "GDB binary analysis and debugging",
      S({{"binary", Ss("Path to binary")},
         {"commands", Ss("GDB commands semicolon-separated", "")},
         {"script_file", Ss("GDB script file", "")},
         {"additional_args", Ss("", "")}},
        {"binary"}));
  add("gdb_peda_debug", "GDB with PEDA for enhanced exploitation debugging",
      S({{"binary", Ss("Binary to debug", "")},
         {"commands", Ss("GDB commands", "")},
         {"attach_pid", Si("PID to attach to", 0)},
         {"core_file", Ss("Core dump file", "")},
         {"additional_args", Ss("", "")}}));
  add("radare2_analyze", "Binary analysis and reverse engineering with Radare2",
      S({{"binary", Ss("Path to binary")},
         {"commands", Ss("r2 commands semicolon-separated", "")},
         {"additional_args", Ss("", "")}},
        {"binary"}));
  add("ghidra_analysis",
      "Advanced binary analysis and decompilation with Ghidra",
      S({{"binary", Ss("Path to binary")},
         {"project_name", Ss("Project name", "mantra_analysis")},
         {"script_file", Ss("Custom Ghidra script", "")},
         {"analysis_timeout", Si("Timeout seconds", 300)},
         {"output_format", Ss("Format: xml json", "xml")},
         {"additional_args", Ss("", "")}},
        {"binary"}));
  add("binwalk_analyze", "Firmware and binary file analysis with Binwalk",
      S({{"file_path", Ss("File to analyze")},
         {"extract", Sb("Extract discovered files")},
         {"additional_args", Ss("", "")}},
        {"file_path"}));
  add("checksec_analyze",
      "Check binary security features (NX, PIE, RELRO, Canary)",
      S({{"binary", Ss("Path to binary")}}, {"binary"}));
  add("strings_extract", "Extract printable strings from binary files",
      S({{"file_path", Ss("File to analyze")},
         {"min_len", Si("Minimum string length", 4)},
         {"additional_args", Ss("", "")}},
        {"file_path"}));
  add("xxd_hexdump", "Hex dump of a file with xxd",
      S({{"file_path", Ss("File to dump")},
         {"offset", Ss("Start offset", "0")},
         {"length", Ss("Bytes to read", "")},
         {"additional_args", Ss("", "")}},
        {"file_path"}));
  add("objdump_analyze", "Binary analysis and disassembly with objdump",
      S({{"binary", Ss("Path to binary")},
         {"disassemble", Sb("Disassemble", true)},
         {"additional_args", Ss("", "")}},
        {"binary"}));
  add("ropgadget_search", "Search for ROP gadgets with ROPgadget",
      S({{"binary", Ss("Path to binary")},
         {"gadget_type", Ss("Gadget type", "")},
         {"additional_args", Ss("", "")}},
        {"binary"}));
  add("ropper_gadget_search", "Advanced ROP/JOP gadget searching with Ropper",
      S({{"binary", Ss("Path to binary")},
         {"gadget_type", Ss("Type: rop jop sys all", "rop")},
         {"quality", Si("Quality level 1-5", 1)},
         {"arch", Ss("Architecture", "")},
         {"search_string", Ss("Gadget pattern to find", "")},
         {"additional_args", Ss("", "")}},
        {"binary"}));
  add("one_gadget_search", "Find one-shot RCE gadgets in libc",
      S({{"libc_path", Ss("Path to libc")},
         {"level", Si("Constraint level 0-2", 1)},
         {"additional_args", Ss("", "")}},
        {"libc_path"}));
  add("pwntools_exploit", "Exploit development and automation with Pwntools",
      S({{"script_content", Ss("Python pwntools script")},
         {"target_binary", Ss("Local binary", "")},
         {"target_host", Ss("Remote host", "")},
         {"target_port", Si("Remote port", 0)},
         {"exploit_type", Ss("Type: local remote format_string rop", "local")},
         {"additional_args", Ss("", "")}}));
  add("angr_symbolic_execution",
      "Symbolic execution and binary analysis with angr",
      S({{"binary", Ss("Binary to analyze")},
         {"script_content", Ss("Custom angr script", "")},
         {"find_address", Ss("Address to find", "")},
         {"avoid_addresses", Ss("Addresses to avoid comma-separated", "")},
         {"analysis_type", Ss("Type: symbolic cfg static", "symbolic")},
         {"additional_args", Ss("", "")}},
        {"binary"}));
  add("pwninit_setup", "CTF binary exploitation setup with pwninit",
      S({{"binary", Ss("Binary file")},
         {"libc", Ss("Libc file", "")},
         {"ld", Ss("Loader file", "")},
         {"template_type", Ss("Template type", "python")},
         {"additional_args", Ss("", "")}},
        {"binary"}));
  add("libc_database_lookup", "Libc identification and offset lookup",
      S({{"action", Ss("Action: find dump download", "find")},
         {"symbols", Ss("Symbols with offsets", "")},
         {"libc_id", Ss("Libc ID", "")},
         {"additional_args", Ss("", "")}}));

  // ── Forensics ──
  add("volatility_analyze", "Memory forensics analysis with Volatility",
      S({{"memory_file", Ss("Memory dump file")},
         {"plugin", Ss("Plugin e.g. imageinfo pslist")},
         {"profile", Ss("Memory profile", "")},
         {"additional_args", Ss("", "")}},
        {"memory_file", "plugin"}));
  add("volatility3_analyze", "Advanced memory forensics with Volatility3",
      S({{"memory_file", Ss("Memory dump file")},
         {"plugin", Ss("Plugin e.g. windows.pslist.PsList")},
         {"output_file", Ss("Output file", "")},
         {"additional_args", Ss("", "")}},
        {"memory_file", "plugin"}));
  add("foremost_carving", "File carving and recovery with Foremost",
      S({{"input_file", Ss("Input file or device")},
         {"output_dir", Ss("Output directory", "/tmp/foremost_output")},
         {"file_types", Ss("File types: jpg gif png", "")},
         {"additional_args", Ss("", "")}},
        {"input_file"}));
  add("steghide_analysis", "Steganography analysis with Steghide",
      S({{"action", Ss("Action: extract embed info")},
         {"cover_file", Ss("Cover file")},
         {"embed_file", Ss("File to embed", "")},
         {"passphrase", Ss("Passphrase", "")},
         {"output_file", Ss("Output file", "")},
         {"additional_args", Ss("", "")}},
        {"action", "cover_file"}));
  add("exiftool_extract", "Metadata extraction with ExifTool",
      S({{"file_path", Ss("File path")},
         {"output_format", Ss("Format: json xml csv", "")},
         {"tags", Ss("Specific tags", "")},
         {"additional_args", Ss("", "")}},
        {"file_path"}));

  // ── Cloud / Containers ──
  add("prowler_scan", "Cloud security assessment with Prowler",
      S({{"provider", Ss("Provider: aws azure gcp", "aws")},
         {"profile", Ss("AWS profile", "default")},
         {"region", Ss("Region", "")},
         {"checks", Ss("Specific checks", "")},
         {"output_dir", Ss("Output directory", "/tmp/prowler_output")},
         {"output_format", Ss("Format: json csv html", "json")},
         {"additional_args", Ss("", "")}}));
  add("trivy_scan",
      "Container and filesystem vulnerability scanning with Trivy",
      S({{"scan_type", Ss("Type: image fs repo config", "image")},
         {"target", Ss("Image name or directory", "")},
         {"output_format", Ss("Format: json table", "json")},
         {"severity", Ss("Severity filter", "")},
         {"output_file", Ss("Output file", "")},
         {"additional_args", Ss("", "")}}));
  add("scout_suite_assessment",
      "Multi-cloud security assessment with Scout Suite",
      S({{"provider", Ss("Provider: aws azure gcp", "aws")},
         {"profile", Ss("AWS profile", "default")},
         {"report_dir", Ss("Report directory", "/tmp/scout-suite")},
         {"services", Ss("Specific services", "")},
         {"additional_args", Ss("", "")}}));
  add("cloudmapper_analysis", "AWS network visualization with CloudMapper",
      S({{"action", Ss("Action: collect prepare webserver", "collect")},
         {"account", Ss("AWS account", "")},
         {"config", Ss("Config file", "config.json")},
         {"additional_args", Ss("", "")}}));
  add("pacu_exploitation", "AWS exploitation framework (Pacu)",
      S({{"session_name", Ss("Session name", "mantra_session")},
         {"modules", Ss("Modules comma-separated", "")},
         {"regions", Ss("AWS regions", "")},
         {"additional_args", Ss("", "")}}));
  add("kube_hunter_scan", "Kubernetes penetration testing with kube-hunter",
      S({{"target", Ss("Target", "")},
         {"remote", Ss("Remote target", "")},
         {"cidr", Ss("CIDR range", "")},
         {"active", Sb("Active hunting")},
         {"report", Ss("Report format", "json")},
         {"additional_args", Ss("", "")}}));
  add("kube_bench_cis", "CIS Kubernetes benchmark checks with kube-bench",
      S({{"targets", Ss("Targets: master node etcd", "")},
         {"version", Ss("K8s version", "")},
         {"output_format", Ss("Format", "json")},
         {"additional_args", Ss("", "")}}));
  add("docker_bench_security_scan",
      "Docker security assessment with Docker Bench",
      S({{"checks", Ss("Specific checks", "")},
         {"exclude", Ss("Checks to exclude", "")},
         {"output_file", Ss("Output file", "/tmp/docker-bench-results.json")},
         {"additional_args", Ss("", "")}}));
  add("clair_vulnerability_scan", "Container vulnerability analysis with Clair",
      S({{"image", Ss("Container image")},
         {"config", Ss("Config file", "/etc/clair/config.yaml")},
         {"output_format", Ss("Format", "json")},
         {"additional_args", Ss("", "")}},
        {"image"}));
  add("falco_runtime_monitoring", "Runtime security monitoring with Falco",
      S({{"config_file", Ss("Config file", "/etc/falco/falco.yaml")},
         {"rules_file", Ss("Rules file", "")},
         {"output_format", Ss("Format", "json")},
         {"duration", Si("Duration seconds", 60)},
         {"additional_args", Ss("", "")}}));
  add("checkov_iac_scan",
      "Infrastructure as code security scanning with Checkov",
      S({{"directory", Ss("Directory to scan", ".")},
         {"framework",
          Ss("Framework: terraform cloudformation kubernetes", "")},
         {"check", Ss("Specific check", "")},
         {"skip_check", Ss("Check to skip", "")},
         {"output_format", Ss("Format", "json")},
         {"additional_args", Ss("", "")}}));
  add("terrascan_iac_scan", "IaC security scanning with Terrascan",
      S({{"scan_type", Ss("Type: all terraform k8s", "all")},
         {"iac_dir", Ss("IaC directory", ".")},
         {"output_format", Ss("Format", "json")},
         {"severity", Ss("Severity filter", "")},
         {"additional_args", Ss("", "")}}));

  // ── AI Payloads ──
  add("ai_generate_payload",
      "Generate AI-powered contextual payloads for security testing",
      S({{"attack_type",
          Ss("Type: xss sqli lfi cmd_injection ssti xxe ssrf rce "
             "privilege_escalation persistence exfiltration")},
         {"complexity", Ss("Level: basic advanced bypass", "basic")},
         {"technology", Ss("Target tech: php asp jsp python nodejs", "")},
         {"url", Ss("Target URL for context", "")}},
        {"attack_type"}));
  add("ai_test_payload",
      "Test generated payload against target with AI analysis",
      S({{"payload", Ss("Payload to test")},
         {"target_url", Ss("Target URL")},
         {"method", Ss("HTTP method", "GET")}},
        {"payload", "target_url"}));
  add("ai_generate_attack_suite",
      "Generate comprehensive attack suite with multiple payload types",
      S({{"target_url", Ss("Target URL")},
         {"attack_types", Ss("Attack types comma-separated", "xss,sqli,lfi")}},
        {"target_url"}));
  add("advanced_payload_generation",
      "Generate advanced payloads with AI evasion techniques",
      S({{"attack_type", Ss("Type: rce privilege_escalation persistence "
                            "exfiltration xss sqli lfi ssrf")},
         {"target_context", Ss("Target environment details", "")},
         {"evasion_level",
          Ss("Level: basic standard advanced nation-state", "standard")},
         {"custom_constraints", Ss("Payload constraints", "")}}));

  // ── CVE Intelligence ──
  add("monitor_cve_feeds", "Monitor CVE databases for new vulnerabilities",
      S({{"hours", Si("Hours to look back", 24)},
         {"severity_filter",
          Ss("Severity: LOW MEDIUM HIGH CRITICAL ALL", "HIGH,CRITICAL")},
         {"keywords", Ss("Filter by keywords", "")}}));
  add("generate_exploit_from_cve", "Generate exploit code from CVE information",
      S({{"cve_id", Ss("CVE identifier e.g. CVE-2024-1234")},
         {"target_os", Ss("OS: windows linux macos", "")},
         {"target_arch", Ss("Arch: x86 x64 arm", "x64")},
         {"exploit_type", Ss("Type: poc weaponized stealth", "poc")},
         {"evasion_level", Ss("Evasion: none basic advanced", "none")}},
        {"cve_id"}));
  add("discover_attack_chains",
      "Discover multi-stage attack chains for target software",
      S({{"target_software", Ss("Target software e.g. Apache HTTP Server 2.4")},
         {"attack_depth", Si("Max chain depth 1-5", 3)},
         {"include_zero_days", Sb("Include zero-day analysis")}},
        {"target_software"}));
  add("research_zero_day_opportunities",
      "Automated zero-day vulnerability research",
      S({{"target_software", Ss("Software to research")},
         {"analysis_depth",
          Ss("Depth: quick standard comprehensive", "standard")},
         {"source_code_url", Ss("Source code repository URL", "")}},
        {"target_software"}));
  add("correlate_threat_intelligence",
      "Correlate threat intelligence across multiple sources",
      S({{"indicators", Ss("Comma-separated IOCs: IPs domains hashes CVEs")},
         {"timeframe", Ss("Time window: 7d 30d 90d 1y", "30d")},
         {"sources", Ss("Sources: cve exploit-db github twitter all", "all")}},
        {"indicators"}));
  add("vulnerability_intelligence_dashboard",
      "Comprehensive vulnerability intelligence dashboard with latest threats",
      S({}));
  add("threat_hunting_assistant",
      "AI-powered threat hunting playbook generation",
      S({{"target_environment",
          Ss("Environment e.g. Windows Domain Cloud Infrastructure")},
         {"threat_indicators", Ss("IOCs comma-separated", "")},
         {"hunt_focus",
          Ss("Focus: general apt ransomware insider_threat supply_chain",
             "general")}},
        {"target_environment"}));

  // ── Intelligence Engine ──
  add("analyze_target_intelligence",
      "Analyze target with AI and create comprehensive profile",
      S({{"target", Ss("Target URL IP or domain")}}, {"target"}));
  add("select_optimal_tools_ai",
      "AI-driven tool selection based on target analysis",
      S({{"target", Ss("Target")},
         {"objective",
          Ss("Objective: comprehensive quick stealth", "comprehensive")}},
        {"target"}));
  add("optimize_tool_parameters_ai",
      "AI-optimized parameters for maximum effectiveness",
      S({{"target", Ss("Target")},
         {"tool", Ss("Tool name e.g. nmap gobuster")},
         {"context", Ss("JSON context string: stealth aggressive", "")}}));
  add("create_attack_chain_ai",
      "Create AI-driven attack chain with tool sequencing",
      S({{"target", Ss("Target")},
         {"objective",
          Ss("Objective: comprehensive quick stealth", "comprehensive")}},
        {"target"}));
  add("intelligent_smart_scan",
      "Execute AI-optimized scan with auto tool selection",
      S({{"target", Ss("Target")},
         {"objective",
          Ss("Objective: comprehensive quick stealth", "comprehensive")},
         {"max_tools", Si("Max tools to use", 5)}},
        {"target"}));
  add("detect_technologies_ai",
      "AI technology detection with testing recommendations",
      S({{"target", Ss("Target")}}, {"target"}));
  add("ai_reconnaissance_workflow", "Full AI-driven reconnaissance workflow",
      S({{"target", Ss("Target")},
         {"depth", Ss("Depth: surface standard deep", "standard")}},
        {"target"}));
  add("ai_vulnerability_assessment",
      "AI-driven vulnerability assessment with prioritization",
      S({{"target", Ss("Target")},
         {"focus_areas", Ss("Focus: web network api all", "all")}},
        {"target"}));

  // ── Bug Bounty ──
  add("bugbounty_reconnaissance_workflow",
      "Complete bug bounty reconnaissance workflow",
      S({{"domain", Ss("Target domain")},
         {"scope", Ss("In-scope domains comma-separated", "")},
         {"out_of_scope", Ss("Out-of-scope comma-separated", "")},
         {"program_type", Ss("Type: web api mobile iot", "web")}},
        {"domain"}));
  add("bugbounty_vulnerability_hunting",
      "Vulnerability hunting workflow by impact and bounty potential",
      S({{"domain", Ss("Target domain")},
         {"priority_vulns",
          Ss("Vuln types comma-separated", "rce,sqli,xss,idor,ssrf")},
         {"bounty_range", Ss("Range: low medium high critical", "unknown")}},
        {"domain"}));
  add("bugbounty_business_logic_testing",
      "Business logic testing workflow for advanced hunting",
      S({{"domain", Ss("Target domain")},
         {"program_type", Ss("Type: web api mobile", "web")}},
        {"domain"}));
  add("bugbounty_osint_gathering",
      "OSINT gathering workflow for bug bounty reconnaissance",
      S({{"domain", Ss("Target domain")}}, {"domain"}));
  add("bugbounty_file_upload_testing",
      "File upload vulnerability testing with bypass techniques",
      S({{"target_url", Ss("Target URL with upload functionality")}},
        {"target_url"}));
  add("bugbounty_comprehensive_assessment",
      "Comprehensive bug bounty assessment with all workflows",
      S({{"domain", Ss("Target domain")},
         {"scope", Ss("In-scope", "")},
         {"priority_vulns", Ss("Priority vulns", "rce,sqli,xss,idor,ssrf")},
         {"include_osint", Sb("Include OSINT", true)},
         {"include_business_logic", Sb("Include business logic", true)}},
        {"domain"}));
  add("bugbounty_authentication_bypass_testing",
      "Authentication bypass testing workflow",
      S({{"target_url", Ss("Target URL with authentication")},
         {"auth_type", Ss("Auth type: form jwt oauth saml", "form")}},
        {"target_url"}));

  // ── Files / Payloads ──
  add("create_file", "Create a file on the mantra server",
      S({{"filename", Ss("Filename")},
         {"content", Ss("File content")},
         {"binary", Sb("Binary content")}},
        {"filename", "content"}));
  add("modify_file", "Modify an existing file on the server",
      S({{"filename", Ss("Filename")},
         {"content", Ss("Content to write or append")},
         {"append", Sb("Append instead of overwrite")}},
        {"filename", "content"}));
  add("delete_file", "Delete a file on the mantra server",
      S({{"filename", Ss("Filename to delete")}}, {"filename"}));
  add("list_files", "List files in a directory on the server",
      S({{"directory", Ss("Directory path", ".")}}));
  add("generate_payload", "Generate test payloads (buffer, cyclic, random)",
      S({{"payload_type", Ss("Type: buffer cyclic random", "buffer")},
         {"size", Si("Size in bytes", 1024)},
         {"pattern", Ss("Pattern for buffer", "A")},
         {"filename", Ss("Custom filename", "")}}));

  // ── Python Env ──
  add("install_python_package",
      "Install a Python package on the mantra server",
      S({{"package", Ss("Package name e.g. pwntools")},
         {"env_name", Ss("Virtual env name", "default")}},
        {"package"}));
  add("execute_python_script",
      "Execute a Python script on the mantra server",
      S({{"script", Ss("Python script content")},
         {"env_name", Ss("Virtual env name", "default")},
         {"filename", Ss("Script filename", "")}},
        {"script"}));

  // ── Process Management ──
  add("list_active_processes", "List all active background processes", S({}));
  add("get_process_status", "Get status of a specific process by PID",
      S({{"pid", Si("Process ID")}}, {"pid"}));
  add("terminate_process", "Terminate a running process",
      S({{"pid", Si("Process ID to terminate")}}, {"pid"}));
  add("pause_process", "Pause (SIGSTOP) a running process",
      S({{"pid", Si("Process ID to pause")}}, {"pid"}));
  add("resume_process", "Resume (SIGCONT) a paused process",
      S({{"pid", Si("Process ID to resume")}}, {"pid"}));
  add("get_process_dashboard",
      "Real-time dashboard with progress bars and system metrics", S({}));
  add("execute_command", "Execute an arbitrary command on the server",
      S({{"command", Ss("Full shell command to execute")},
         {"use_cache", Sb("Use command cache", true)}},
        {"command"}));

  // ── Monitoring ──
  add("server_health", "Check mantra AI server health and tool availability",
      S({}));
  add("get_cache_stats", "Get cache performance statistics", S({}));
  add("clear_cache", "Clear the server result cache", S({}));
  add("get_telemetry", "Get system performance and usage telemetry", S({}));

  // ── Visual Output ──
  add("get_live_dashboard",
      "Live dashboard with process monitoring and system metrics", S({}));
  add("create_vulnerability_report",
      "Create formatted vulnerability report with severity styling",
      S({{"vulnerabilities", Ss("JSON array of vulnerability objects")},
         {"target", Ss("Scanned target", "")},
         {"scan_type", Ss("Scan type", "comprehensive")}},
        {"vulnerabilities"}));
  add("format_tool_output_visual",
      "Format tool output with visual styling and syntax highlighting",
      S({{"tool_name", Ss("Tool name")},
         {"output", Ss("Raw tool output")},
         {"success", Sb("Was execution successful", true)}},
        {"tool_name", "output"}));
  add("create_scan_summary", "Create comprehensive scan summary report",
      S({{"target", Ss("Scanned target")},
         {"tools_used", Ss("Tools comma-separated")},
         {"vulnerabilities_found", Si("Number of vulnerabilities", 0)},
         {"execution_time",
          {{"type", "number"},
           {"description", "Execution time seconds"},
           {"default", 0.0}}}},
        {"target", "tools_used"}));
  add("display_system_metrics",
      "Display system performance metrics with visual formatting", S({}));

  // ── Error Handling ──
  add("error_handling_statistics",
      "Get intelligent error handling statistics and patterns", S({}));
  add("test_error_recovery",
      "Test error recovery system with simulated failures",
      S({{"tool_name", Ss("Tool to simulate error for", "nmap")},
         {"error_type", Ss("Error type: timeout permission_denied "
                           "network_unreachable rate_limited",
                           "timeout")},
         {"target", Ss("Test target", "example.com")}}));

  // ── API Security ──
  add("graphql_scanner", "Advanced GraphQL security scanning and introspection",
      S({{"endpoint", Ss("GraphQL endpoint URL")},
         {"introspection", Sb("Test introspection", true)},
         {"query_depth", Si("Max query depth", 10)},
         {"test_mutations", Sb("Test mutations", true)}},
        {"endpoint"}));
  add("jwt_analyzer", "Advanced JWT token analysis and vulnerability testing",
      S({{"jwt_token", Ss("JWT token to analyze")},
         {"target_url", Ss("Target URL for testing", "")}},
        {"jwt_token"}));
  add("api_fuzzer", "Advanced API endpoint fuzzing with parameter discovery",
      S({{"base_url", Ss("Base URL of the API")},
         {"endpoints", Ss("Specific endpoints comma-separated", "")},
         {"methods", Ss("HTTP methods comma-separated", "GET,POST,PUT,DELETE")},
         {"wordlist", Ss("Endpoint wordlist", "")}}));
  add("api_schema_analyzer", "Analyze API schemas and identify security issues",
      S({{"schema_url", Ss("URL to OpenAPI/Swagger schema")},
         {"schema_type", Ss("Type: openapi swagger graphql", "openapi")}},
        {"schema_url"}));
  add("comprehensive_api_audit",
      "Full API security audit combining multiple techniques",
      S({{"base_url", Ss("Base API URL")},
         {"schema_url", Ss("Optional schema URL", "")},
         {"jwt_token", Ss("Optional JWT token", "")},
         {"graphql_endpoint", Ss("Optional GraphQL endpoint", "")}},
        {"base_url"}));

  // ── HTTP Framework Helpers ──
  add("http_set_rules", "Set match/replace rules for HTTP request rewriting",
      S({{"rules", Sa("Array of rule objects with where/pattern/replacement")}},
        {"rules"}));
  add("http_set_scope", "Define in-scope host for HTTP framework",
      S({{"host", Ss("In-scope hostname")},
         {"include_subdomains", Sb("Include subdomains", true)}},
        {"host"}));
  add("http_repeater", "Send a crafted HTTP request (Burp Repeater equivalent)",
      S({{"request_spec",
          {{"type", "object"},
           {"description", "Request spec: url method headers cookies data"}}}},
        {"request_spec"}));
  add("http_intruder", "Simple sniper fuzzing (Burp Intruder equivalent)",
      S({{"url", Ss("Target URL")},
         {"method", Ss("HTTP method", "GET")},
         {"location", Ss("Location: query body headers cookie", "query")},
         {"params", Sa("Parameters to fuzz")},
         {"payloads", Sa("Payloads to use")},
         {"max_requests", Si("Max requests", 100)}},
        {"url", "payloads"}));

  return tools;
}

// ============================================================================
// MCP JSON-RPC request handler — protocol v0.1.0 / 2024-11-05
// ============================================================================
json handle_request(const json &req) {
  std::string method = req.value("method", "");

  // Notifications (no id) never get a response per JSON-RPC spec
  if (method.rfind("notifications/", 0) == 0)
    return json();

  json resp;
  resp["jsonrpc"] = "2.0";
  if (req.contains("id"))
    resp["id"] = req["id"];

  if (method == "initialize") {
    resp["result"] = {
        {"protocolVersion", "2024-11-05"},
        {"capabilities", {{"tools", {{"listChanged", false}}}}},
        {"serverInfo",
         {{"name", "mantra-mcp-bridge"}, {"version", "6.0.0"}}}};
    log(Log::INFO,
        std::string(Col::SUCCESS) + "✅ MCP handshake complete" + Col::RESET);
  } else if (method == "tools/list") {
    static json tool_defs = build_tool_definitions();
    resp["result"] = {{"tools", tool_defs}};
    log(Log::DEBUG,
        "tools/list: returned " + std::to_string(tool_defs.size()) + " tools");
  } else if (method == "tools/call") {
    if (!req.contains("params") || !req["params"].contains("name") ||
        !req["params"]["name"].is_string()) {
      resp["error"] = {{"code", -32602},
                       {"message", "Invalid params: 'name' (string) required"}};
      return resp;
    }
    std::string tool_name = req["params"]["name"].get<std::string>();
    json args = req["params"].value("arguments", json::object());

    log(Log::INFO,
        std::string(Col::FIRE_RED) + "🔧 Tool call: " + tool_name + Col::RESET);
    auto it = TOOL_DISPATCH.find(tool_name);
    if (it != TOOL_DISPATCH.end()) {
      try {
        json result = it->second(args);
        std::string text = result.dump(2);
        resp["result"] = {{"content", {{{"type", "text"}, {"text", text}}}},
                          {"isError", false}};
      } catch (const std::exception &e) {
        log(Log::ERROR, "Tool exception: " + std::string(e.what()));
        resp["result"] = {{"content",
                           {{{"type", "text"},
                             {"text", "ERROR: " + std::string(e.what())}}}},
                          {"isError", true}};
      }
    } else {
      log(Log::ERROR, "Unknown tool: " + tool_name);
      resp["error"] = {{"code", -32601},
                       {"message", "Unknown tool: " + tool_name}};
    }
  } else if (method == "ping") {
    resp["result"] = json::object();
  } else if (method == "resources/list") {
    resp["result"] = {{"resources", json::array()}};
  } else if (method == "prompts/list") {
    resp["result"] = {{"prompts", json::array()}};
  } else {
    resp["error"] = {{"code", -32601},
                     {"message", "Method not found: " + method}};
  }
  return resp;
}

// ============================================================================
// CLI argument parsing
// ============================================================================
void parse_args(int argc, char *argv[]) {
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if ((arg == "--server" || arg == "-s") && i + 1 < argc) {
      g_server_url = argv[++i];
    } else if ((arg == "--timeout" || arg == "-t") && i + 1 < argc) {
      g_timeout_sec = std::stoi(argv[++i]);
    } else if (arg == "--debug" || arg == "-d") {
      g_debug = true;
    } else if (arg == "--help" || arg == "-h") {
      std::cerr
          << "mantra MCP Bridge v6.0\n"
          << "Usage: mantra_bridge [OPTIONS]\n\n"
          << "Options:\n"
          << "  --server URL    mantra server URL (default: "
             "http://127.0.0.1:8888)\n"
          << "  --timeout SEC   Request timeout in seconds (default: 300)\n"
          << "  --debug         Enable debug logging\n"
          << "  --help          Show this help\n\n"
          << "Reads MCP JSON-RPC from stdin, writes responses to stdout.\n"
          << "Configure in your AI tool's MCP settings — see comments below.\n";
      exit(0);
    }
  }
}

// ============================================================================
// Main — stdin/stdout MCP JSON-RPC loop
// ============================================================================
int main(int argc, char *argv[]) {
  parse_args(argc, argv);
  curl_global_init(CURL_GLOBAL_DEFAULT);

  // Disable stdout buffering for real-time MCP communication
  std::cout.setf(std::ios::unitbuf);

  // Log startup info to stderr (matches Python main() output)
  log(Log::INFO, "🚀 Starting mantra AI MCP Bridge v6.0");
  log(Log::INFO, "🔗 Connecting to: " + g_server_url +
                     " (timeout: " + std::to_string(g_timeout_sec) + "s)");

  // Connection check with retries — matches Python MAX_RETRIES logic
  bool connected = check_connection();
  if (!connected) {
    log(Log::WARNING, "⚠️  Unable to connect to server — bridge will start "
                      "anyway but tool calls may fail");
    log(Log::WARNING,
        "🚀 Make sure main.cpp server is running: ./mantra [port]");
  }

  log(Log::INFO,
      std::string(Col::HL_GREEN) + " mantra MCP Bridge ready — serving " +
          std::to_string(TOOL_DISPATCH.size()) + " tools " + Col::RESET);
  log(Log::INFO,
      "🤖 Ready to serve AI agents with enhanced cybersecurity capabilities");

  // Main MCP JSON-RPC loop
  std::string line;
  while (std::getline(std::cin, line)) {
    if (line.empty())
      continue;
    try {
      json req = json::parse(line);
      json resp = handle_request(req);
      if (!resp.is_null()) {
        std::cout << resp.dump() << "\n";
      }
    } catch (const json::parse_error &e) {
      log(Log::DEBUG, "Parse error: " + std::string(e.what()));
      json err;
      err["jsonrpc"] = "2.0";
      err["id"] = nullptr;
      err["error"] = {{"code", -32700}, {"message", "Parse error"}};
      std::cout << err.dump() << "\n";
    } catch (const std::exception &e) {
      log(Log::ERROR, "Request handler exception: " + std::string(e.what()));
      json err;
      err["jsonrpc"] = "2.0";
      err["id"] = nullptr;
      err["error"] = {{"code", -32603}, {"message", "Internal error: " + std::string(e.what())}};
      std::cout << err.dump() << "\n";
    }
  }

  curl_global_cleanup();
  return 0;
}

/*
============================================================================
TESTING WITH AI AGENTS — Quick Setup Guide
============================================================================

STEP 1 — Build both binaries:
  apt install build-essential libcurl4-openssl-dev

  # Get single-header deps (place in same directory as .cpp files)
  wget
https://raw.githubusercontent.com/nlohmann/json/develop/single_include/nlohmann/json.hpp
  wget https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h

  # Build the server (main.cpp)
  g++ -std=c++17 -pthread main.cpp -lcurl -o mantra

  # Build the MCP bridge (this file)
  g++ -std=c++17 mcp_bridge.cpp -lcurl -o mantra_bridge

STEP 2 — Start the server:
  ./mantra                    # Listens on port 8888 by default
  ./mantra 9999               # Custom port

STEP 3 — Test manually:
  echo
'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
\ | ./mantra_bridge

  echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
    | ./mantra_bridge

  echo
'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"server_health","arguments":{}}}'
\ | ./mantra_bridge

  echo
'{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nmap_scan","arguments":{"target":"scanme.nmap.org","scan_type":"-sV"}}}'
\ | ./mantra_bridge

============================================================================
CLAUDE DESKTOP (macOS/Linux/Windows)
File: ~/Library/Application Support/Claude/claude_desktop_config.json
============================================================================
{
  "mcpServers": {
    "mantra": {
      "command": "/path/to/mantra_bridge",
      "args": ["--server", "http://127.0.0.1:8888"],
      "env": {}
    }
  }
}

============================================================================
CURSOR IDE
File: ~/.cursor/mcp.json  OR  <project>/.cursor/mcp.json
============================================================================
{
  "mcpServers": {
    "mantra": {
      "command": "/path/to/mantra_bridge",
      "args": ["--server", "http://127.0.0.1:8888", "--timeout", "300"]
    }
  }
}

============================================================================
WINDSURF (Codeium)
File: ~/.codeium/windsurf/mcp_config.json
============================================================================
{
  "mcpServers": {
    "mantra": {
      "command": "/path/to/mantra_bridge",
      "args": ["--server", "http://127.0.0.1:8888"]
    }
  }
}

============================================================================
CLINE (VS Code Extension)
VS Code settings.json:
============================================================================
{
  "cline.mcpServers": {
    "mantra": {
      "command": "/path/to/mantra_bridge",
      "args": ["--server", "http://127.0.0.1:8888"]
    }
  }
}

============================================================================
CONTINUE.DEV
File: ~/.continue/config.json
============================================================================
{
  "mcpServers": [
    {
      "name": "mantra",
      "command": "/path/to/mantra_bridge",
      "args": ["--server", "http://127.0.0.1:8888"]
    }
  ]
}

============================================================================
AIDER
Run with MCP server flag:
  aider --mcp-server "/path/to/mantra_bridge --server http://127.0.0.1:8888"

============================================================================
GITHUB COPILOT (VS Code — requires MCP extension)
File: .vscode/mcp.json in workspace:
============================================================================
{
  "servers": {
    "mantra": {
    "type": "stdio",
      "command": "/path/to/mantra_bridge",
      "args": ["--server", "http://127.0.0.1:8888"]
    }
  }
}

============================================================================
ANTIGRAVITY / ANY MCP-COMPATIBLE CLIENT
Generic stdio MCP configuration:
============================================================================
{
  "name": "MANTRA Security Suite",
  "command": "/path/to/mantra_bridge",
  "args": [
    "--server", "http://127.0.0.1:8888",
    "--timeout", "300"
  ],
  "transport": "stdio",
  "protocol": "mcp/2024-11-05"
}

============================================================================
DOCKER DEPLOYMENT (bridge + server together)
Dockerfile snippet:
============================================================================
FROM kalilinux/kali-rolling

RUN apt update && apt install -y build-essential libcurl4-openssl-dev nmap \
    gobuster nuclei sqlmap nikto curl wget python3 python3-pip

COPY main.cpp mcp_bridge.cpp httplib.h json.hpp /app/
WORKDIR /app

RUN g++ -std=c++17 -pthread main.cpp -lcurl -o mantra && \
    g++ -std=c++17 mcp_bridge.cpp -lcurl -o mantra_bridge

# Start server in background, bridge in foreground (for MCP)
CMD ["/bin/bash", "-c", "./mantra 8888 &>/tmp/mantra.log & ./mantra_bridge"]

============================================================================
REMOTE SERVER + LOCAL BRIDGE (tunnel setup)
If the MANTRA server is on a remote machine:
  ssh -L 8888:localhost:8888 user@remote-server  # SSH tunnel
  ./mantra_bridge --server http://localhost:8888

Or with ngrok:
  ngrok http 8888  # on the server
  ./mantra_bridge --server https://your-ngrok-url.ngrok.io

============================================================================
QUICK VERIFICATION COMMANDS
============================================================================

# 1. Verify server is running
curl http://localhost:8888/health

# 2. Run a quick nmap scan
curl -X POST http://localhost:8888/api/tools/nmap \
  -H "Content-Type: application/json" \
  -d '{"target":"scanme.nmap.org","scan_type":"-sV"}'

# 3. Generate XSS payloads
curl -X POST http://localhost:8888/api/ai/generate_payload \
  -H "Content-Type: application/json" \
  -d '{"attack_type":"xss","complexity":"advanced"}'

# 4. CVE intelligence feed
curl http://localhost:8888/api/vuln-intel/cve-monitor \
  -X POST -H "Content-Type: application/json" \
  -d '{"hours":24,"severity_filter":"CRITICAL"}'

# 5. Test MCP bridge directly
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | ./mantra_bridge | python3 -m json.tool | head -40

============================================================================
*/
