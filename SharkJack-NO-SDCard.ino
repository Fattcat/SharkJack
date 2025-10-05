/*
  Povolené (whitelist) príkazy:
    - PING <ip_or_single>         -> simulované ako TCP_CHECK na port 80 (bez data), krátky timeout
    - TCP_CHECK <ip> <port>       -> kontrola pripojiteľnosti (len povolené porty)
    - HTTP_HEAD <ip_orhost>       -> vykoná HTTP HEAD na port 80 (získa status line a Server header ak existuje)
    - READ <filename>             -> číta lokálny súbor zo SD (a zapisuje riadky do loot.txt)
    - WRITE <filename> "<text>"   -> prepíše súbor
    - APPEND <filename> "<text>"  -> dopíše do súboru
    - SLEEP <ms>                  -> delay (safety cap)
    - NOP                         -> nič
  Zakázané: masívne skeny, SSH/FTP/SMB probing a pod.

  CS_ENC = D10, CS_SD = D8 -- zmeň podľa zapojenia.
*/

#include <SPI.h>
#include <SD.h>
#include <UIPEthernet.h>   // pre ENC28J60 (UIPEthernet)

#define CS_ENC   10
#define CS_SD     8
#define LED_PIN  13  // built-in LED on Arduino Nano

// MAC pre Ethernet (upraviť ak potrebuješ unikátnu MAC)
byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };

// Konfigurácia autorizovaného subnetu (jednoduché checkovanie prefixu 192.168.1.x)
const uint8_t AUTH_PREFIX[3] = {192, 168, 1}; // povolený prefix (3 oktety)
const int AUTH_PREFIX_LEN = 3;

// Povolené TCP porty pre TCP_CHECK
const uint16_t ALLOWED_PORTS[] = {80, 443, 8080};
const size_t ALLOWED_PORTS_COUNT = sizeof(ALLOWED_PORTS)/sizeof(ALLOWED_PORTS[0]);

// Timeouty
const unsigned long TCP_CHECK_TIMEOUT = 250; // ms
const unsigned long HTTP_HEAD_TIMEOUT = 400; // ms
const unsigned long MAX_SLEEP_MS = 60000;    // cap pre SLEEP

// Buffers
const size_t LINE_BUF = 160;
char linebuf[LINE_BUF+1];

// Globálne stavy
bool sdReady = false;
bool ethReady = false;

// ================= SETUP =================
void setup() {
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  
  Serial.begin(115200);
  while (!Serial) { ; }

  // Nastav CS piny ako OUTPUT a deselect
  pinMode(CS_ENC, OUTPUT); digitalWrite(CS_ENC, HIGH);
  pinMode(CS_SD, OUTPUT);  digitalWrite(CS_SD, HIGH);

  SPI.begin(); // inicializuje SPI

  // Inicializuj Ethernet (DHCP)
  Serial.println("Initializing Ethernet (DHCP) ...");
  Ethernet.init(CS_ENC);
  if (Ethernet.begin(mac) == 0) {
    Serial.println("DHCP failed, using static IP fallback (192.168.1.200)");
    IPAddress fallback(192,168,1,200);
    Ethernet.begin(mac, fallback);
  }
  delay(1000);
  IPAddress myIP = Ethernet.localIP();
  if (myIP != INADDR_NONE && myIP[0] != 0) {
    ethReady = true;
    Serial.print("IP: "); Serial.println(myIP);
  } else {
    ethReady = false;
    Serial.println("Ethernet init FAILED!");
  }

  // Inicializuj SD
  Serial.println("Initializing SD...");
  if (SD.begin(CS_SD)) {
    sdReady = true;
    Serial.println("SD initialized.");
  } else {
    sdReady = false;
    Serial.println("SD init FAILED!");
  }

  Serial.println("\nReady! Enter commands below:");
}

// ================= LOOP =================
void loop() {
  static unsigned long lastBlink = 0;
  static bool ledState = false;

  unsigned long now = millis();

  if (sdReady && ethReady) {
    if (now - lastBlink >= 500) {
      ledState = !ledState;
      digitalWrite(LED_PIN, ledState);
      lastBlink = now;
    }
  } else if (!sdReady) {
    if (now - lastBlink >= 100) {
      ledState = !ledState;
      digitalWrite(LED_PIN, ledState);
      lastBlink = now;
    }
  } else if (!ethReady) {
    if (now - lastBlink >= 2000) {
      ledState = !ledState;
      digitalWrite(LED_PIN, ledState);
      lastBlink = now;
    }
  }

  // Čítaj príkaz z Serial
  if (Serial.available()) {
    String input = Serial.readStringUntil('\n');
    input.trim();
    if (input.length() > 0) {
      input.toCharArray(linebuf, LINE_BUF);
      bool authorized = ethReady && inAuthorizedSubnet(Ethernet.localIP());
      handleCommandLine(linebuf, authorized);
    }
  }
}

// ================= helpery =================

unsigned long now_ms() {
  return millis();
}

void appendLoot(const char* tag, const char* target, const char* result, const char* details) {
  // Loguj do Serialu
  Serial.print("[LOOT] ");
  Serial.print(now_ms());
  Serial.print(" | ");
  Serial.print(tag);
  Serial.print(" | ");
  Serial.print(target ? target : "-");
  Serial.print(" | ");
  Serial.print(result ? result : "-");
  Serial.print(" | ");
  Serial.println(details ? details : "-");

  // Loguj do loot.txt ak je SD OK
  if (sdReady) {
    if (!SD.exists("loot.txt")) {
      File f = SD.open("loot.txt", FILE_WRITE);
      if (f) f.close();
    }
    File out = SD.open("loot.txt", FILE_WRITE);
    if (out) {
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
  }
}

bool inAuthorizedSubnet(IPAddress ip) {
  for (int i = 0; i < AUTH_PREFIX_LEN; i++) {
    if (ip[i] != AUTH_PREFIX[i]) return false;
  }
  return true;
}

bool portAllowed(uint16_t p) {
  for (size_t i = 0; i < ALLOWED_PORTS_COUNT; i++)
    if (ALLOWED_PORTS[i] == p) return true;
  return false;
}

bool parseIP(const char* s, IPAddress &out) {
  int parts[4] = {0,0,0,0};
  int idx = 0;
  const char* p = s;
  char num[4];
  int nidx = 0;
  int part = 0;
  while (*p && part < 4) {
    if (*p == '.') {
      num[nidx] = 0;
      parts[part++] = atoi(num);
      nidx = 0;
    } else {
      if (nidx < 3) num[nidx++] = *p;
    }
    p++;
  }
  if (nidx > 0 && part < 4) {
    num[nidx] = 0;
    parts[part++] = atoi(num);
  }
  if (part != 4) return false;
  for (int i = 0; i < 4; i++)
    if (parts[i] < 0 || parts[i] > 255) return false;
  out = IPAddress(parts[0], parts[1], parts[2], parts[3]);
  return true;
}

// ================= sieťové operácie (bezpečné) =================

bool safe_tcp_check(const IPAddress &ip, uint16_t port, unsigned long timeout, char* out_details, size_t details_len) {
  if (!portAllowed(port)) {
    strncpy(out_details, "PORT_NOT_ALLOWED", details_len - 1);
    out_details[details_len - 1] = 0;
    return false;
  }
  EthernetClient client;
  unsigned long start = now_ms();
  bool ok = client.connect(ip, port);
  while (!ok && (now_ms() - start) < timeout) {
    delay(5);
    ok = client.connect(ip, port);
  }
  if (ok) {
    client.stop();
    strncpy(out_details, "OPEN", details_len - 1);
    out_details[details_len - 1] = 0;
    return true;
  } else {
    strncpy(out_details, "CLOSED_TIMEOUT", details_len - 1);
    out_details[details_len - 1] = 0;
    return false;
  }
}

bool safe_http_head(const IPAddress &ip, char* out_summary, size_t sum_len) {
  const uint16_t port = 80;
  if (!portAllowed(port)) {
    strncpy(out_summary, "PORT_NOT_ALLOWED", sum_len - 1);
    out_summary[sum_len - 1] = 0;
    return false;
  }
  EthernetClient client;
  unsigned long start = now_ms();
  if (!client.connect(ip, port)) {
    while ((now_ms() - start) < HTTP_HEAD_TIMEOUT) {
      delay(5);
      if (client.connect(ip, port)) break;
    }
  }
  if (!client.connected()) {
    strncpy(out_summary, "CONNECT_FAIL", sum_len - 1);
    out_summary[sum_len - 1] = 0;
    client.stop();
    return false;
  }
  client.print("HEAD / HTTP/1.0\r\nHost: ");
  client.print(ip);
  client.print("\r\nConnection: close\r\n\r\n");

  unsigned long tstart = now_ms();
  bool gotStatus = false;
  char serverHdr[80]; serverHdr[0] = 0;
  char statusLine[80]; statusLine[0] = 0;
  String line;

  while (client.connected() && (now_ms() - tstart) < HTTP_HEAD_TIMEOUT) {
    if (client.available()) {
      line = client.readStringUntil('\n');
      line.trim();
      if (!gotStatus) {
        line.toCharArray(statusLine, sizeof(statusLine));
        gotStatus = true;
      }
      if (line.startsWith("Server:")) {
        line.substring(7).trim().toCharArray(serverHdr, sizeof(serverHdr));
      }
      if (line.length() == 0) break;
    }
  }
  client.stop();
  if (!gotStatus) {
    strncpy(out_summary, "NO_STATUS", sum_len - 1);
    out_summary[sum_len - 1] = 0;
    return false;
  }
  if (serverHdr[0] != 0) {
    snprintf(out_summary, sum_len, "STATUS:%s;SERVER:%s", statusLine, serverHdr);
  } else {
    snprintf(out_summary, sum_len, "STATUS:%s", statusLine);
  }
  return true;
}

// ================= parsovanie a vykonanie príkazu =================

void trim_leadtrail(char* s) {
  int i = 0;
  while (s[i] == ' ' || s[i] == '\t') i++;
  if (i > 0) memmove(s, s + i, strlen(s + i) + 1);
  int len = strlen(s);
  while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t')) s[--len] = 0;
}

void handleCommandLine(char* rawline, bool authorized) {
  trim_leadtrail(rawline);
  if (rawline[0] == 0) return;
  if (rawline[0] == '#') return;
  int rl = strlen(rawline);
  if (rl > 0 && rawline[rl - 1] == ';') rawline[rl - 1] = 0;

  char copyLine[LINE_BUF + 1];
  strncpy(copyLine, rawline, LINE_BUF);
  copyLine[LINE_BUF] = 0;

  char *token = strtok(copyLine, " ");
  if (!token) return;
  for (char* p = token; *p; ++p)
    if (*p >= 'a' && *p <= 'z') *p = *p - 'a' + 'A';

  if (strcmp(token, "NOP") == 0) {
    appendLoot("NOP", "-", "OK", "NOP executed");
    return;
  }

  if (strcmp(token, "SLEEP") == 0) {
    char* arg = strtok(NULL, " ");
    if (!arg) {
      appendLoot("SLEEP", "-", "BAD_PARAM", "missing ms");
      return;
    }
    unsigned long ms = atol(arg);
    if (ms > MAX_SLEEP_MS) ms = MAX_SLEEP_MS;
    delay(ms);
    appendLoot("SLEEP", "-", "OK", "slept");
    return;
  }

  if (strcmp(token, "READ") == 0) {
    char* fname = strtok(NULL, " ");
    if (!fname) {
      appendLoot("READ", "-", "BAD_PARAM", "missing filename");
      return;
    }
    trim_leadtrail(fname);
    if (!sdReady) {
      appendLoot("READ", fname, "ERROR", "SD not ready");
      return;
    }
    File in = SD.open(fname, FILE_READ);
    if (!in) {
      appendLoot("READ", fname, "OPEN_FAIL", "cannot open");
      return;
    }
    char rline[120];
    size_t ridx = 0;
    while (in.available()) {
      char ch = in.read();
      if (ch == '\r') continue;
      if (ch == '\n' || ridx >= sizeof(rline) - 2) {
        rline[ridx] = 0;
        appendLoot("READLINE", fname, "OK", rline);
        ridx = 0;
      } else rline[ridx++] = ch;
    }
    if (ridx > 0) {
      rline[ridx] = 0;
      appendLoot("READLINE", fname, "OK", rline);
    }
    in.close();
    appendLoot("READ", fname, "DONE", "read complete");
    return;
  }

  if (strcmp(token, "WRITE") == 0 || strcmp(token, "APPEND") == 0) {
    if (!sdReady) {
      appendLoot(token, "-", "ERROR", "SD not ready");
      return;
    }
    char* fname = strtok(NULL, " ");
    char* rest = strtok(NULL, "");
    if (!fname || !rest) {
      appendLoot(token, "-", "BAD_PARAM", "missing args");
      return;
    }
    trim_leadtrail(rest);
    if (rest[0] == '"') {
      size_t l = strlen(rest);
      if (rest[l - 1] == '"') {
        rest[l - 1] = 0;
        rest++;
      }
    }
    File fo = SD.open(fname, FILE_WRITE);
    if (!fo) {
      appendLoot(token, fname, "OPEN_FAIL", "cannot open");
      return;
    }
    if (strcmp(token, "WRITE") == 0) {
      fo.seek(0);
      fo.print(rest);
    } else {
      fo.println(rest);
    }
    fo.close();
    appendLoot(token, fname, "OK", rest);
    return;
  }

  if (!authorized) {
    appendLoot("NETCMD", rawline, "SKIPPED", "not in authorized subnet");
    return;
  }

  if (strcmp(token, "PING") == 0) {
    char* target = strtok(NULL, " ");
    if (!target) {
      appendLoot("PING", "-", "BAD_PARAM", "missing target");
      return;
    }
    IPAddress ip;
    if (!parseIP(target, ip)) {
      appendLoot("PING", target, "BAD_PARAM", "invalid ip");
      return;
    }
    char details[64];
    bool res = safe_tcp_check(ip, 80, TCP_CHECK_TIMEOUT, details, sizeof(details));
    appendLoot("PING", target, res ? "UP" : "DOWN", details);
    return;
  }

  if (strcmp(token, "TCP_CHECK") == 0) {
    char* target = strtok(NULL, " ");
    char* portS = strtok(NULL, " ");
    if (!target || !portS) {
      appendLoot("TCP_CHECK", "-", "BAD_PARAM", "missing args");
      return;
    }
    IPAddress ip;
    if (!parseIP(target, ip)) {
      appendLoot("TCP_CHECK", target, "BAD_PARAM", "invalid ip");
      return;
    }
    uint16_t port = atoi(portS);
    char details[64];
    bool ok = safe_tcp_check(ip, port, TCP_CHECK_TIMEOUT, details, sizeof(details));
    appendLoot("TCP_CHECK", target, ok ? "OPEN" : "CLOSED", details);
    return;
  }

  if (strcmp(token, "HTTP_HEAD") == 0) {
    char* target = strtok(NULL, " ");
    if (!target) {
      appendLoot("HTTP_HEAD", "-", "BAD_PARAM", "missing target");
      return;
    }
    IPAddress ip;
    if (!parseIP(target, ip)) {
      appendLoot("HTTP_HEAD", target, "BAD_PARAM", "invalid ip");
      return;
    }
    char summary[160];
    if (safe_http_head(ip, summary, sizeof(summary))) {
      appendLoot("HTTP_HEAD", target, "OK", summary);
    } else {
      appendLoot("HTTP_HEAD", target, "FAIL", summary);
    }
    return;
  }

  appendLoot("UNKNOWN_CMD", rawline, "IGNORED", "not in whitelist");
}
