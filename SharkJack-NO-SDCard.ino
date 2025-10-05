/*
  Povolené (whitelist) príkazy (po zadaní "start"):
    - PING <ip>                   -> TCP_CHECK na port 80
    - TCP_CHECK <ip> <port>       -> kontrola pripojiteľnosti (len povolené porty: 80,443,8080)
    - HTTP_HEAD <ip>              -> HTTP HEAD na port 80
    - READ <filename>             -> NEDOSTUPNÉ (bez SD)
    - WRITE <filename> "<text>"   -> NEDOSTUPNÉ
    - APPEND <filename> "<text>"  -> NEDOSTUPNÉ
    - SLEEP <ms>                  -> delay (max 60s)
    - NOP                         -> nič

  Zakázané: masívne skeny, SSH/FTP/SMB probing a pod.

  CS_ENC = D10 -- zmeň podľa zapojenia.
*/

#include <SPI.h>
#include <UIPEthernet.h>   // pre ENC28J60

#define CS_ENC   10
#define LED_PIN  13

// MAC adresa
byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };

// Povolený subnet: 192.168.1.x
const uint8_t AUTH_PREFIX[3] = {192, 168, 1};
const int AUTH_PREFIX_LEN = 3;

// Povolené porty
const uint16_t ALLOWED_PORTS[] = {80, 443, 8080};
const size_t ALLOWED_PORTS_COUNT = sizeof(ALLOWED_PORTS)/sizeof(ALLOWED_PORTS[0]);

// Timeouty
const unsigned long TCP_CHECK_TIMEOUT = 250;
const unsigned long HTTP_HEAD_TIMEOUT = 400;
const unsigned long MAX_SLEEP_MS = 60000;

// Buffers
const size_t LINE_BUF = 160;
char linebuf[LINE_BUF + 1];

// Stavy
bool ethReady = false;
bool started = false; // čaká na "start"

// ================= SETUP =================
void setup() {
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);

  Serial.begin(115200);
  while (!Serial) { ; }

  pinMode(CS_ENC, OUTPUT);
  digitalWrite(CS_ENC, HIGH);
  SPI.begin();

  // Ethernet (DHCP)
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

  Serial.println("\nSystem ready. Type 'start' to begin.");
}

// ================= LOOP =================
void loop() {
  static unsigned long lastBlink = 0;
  static bool ledState = false;
  unsigned long now = millis();

  // LED indikátor
  if (ethReady) {
    if (now - lastBlink >= 500) {
      ledState = !ledState;
      digitalWrite(LED_PIN, ledState);
      lastBlink = now;
    }
  } else {
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

    if (input.length() == 0) {
      if (!started) Serial.println("waiting for command ...");
      return;
    }

    // Pred "start" – iba príkaz "start" je povolený
    if (!started) {
      if (input.equalsIgnoreCase("start")) {
        started = true;
        Serial.println("Command mode activated. Ready for commands.");
      } else {
        Serial.println("bad input command");
      }
      return;
    }

    // Po "start" – spracuj príkaz
    input.toCharArray(linebuf, LINE_BUF);
    bool authorized = ethReady && inAuthorizedSubnet(Ethernet.localIP());
    handleCommandLine(linebuf, authorized);
  }
}

// ================= Helper funkcie =================

unsigned long now_ms() {
  return millis();
}

void logToSerial(const char* tag, const char* target, const char* result, const char* details) {
  Serial.print("[");
  Serial.print(tag);
  Serial.print("] ");
  Serial.print(target ? target : "-");
  Serial.print(" | ");
  Serial.print(result ? result : "-");
  Serial.print(" | ");
  Serial.println(details ? details : "-");
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

void trim_leadtrail(char* s) {
  int i = 0;
  while (s[i] == ' ' || s[i] == '\t') i++;
  if (i > 0) memmove(s, s + i, strlen(s + i) + 1);
  int len = strlen(s);
  while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t')) s[--len] = 0;
}

void handleCommandLine(char* rawline, bool authorized) {
  trim_leadtrail(rawline);
  if (rawline[0] == 0 || rawline[0] == '#') return;
  int rl = strlen(rawline);
  if (rl > 0 && rawline[rl - 1] == ';') rawline[rl - 1] = 0;

  char copyLine[LINE_BUF + 1];
  strncpy(copyLine, rawline, LINE_BUF);
  copyLine[LINE_BUF] = 0;

  char *token = strtok(copyLine, " ");
  if (!token) return;

  // Prevod na uppercase
  for (char* p = token; *p; ++p)
    if (*p >= 'a' && *p <= 'z') *p = *p - 'a' + 'A';

  if (strcmp(token, "NOP") == 0) {
    logToSerial("NOP", "-", "OK", "NOP executed");
    return;
  }

  if (strcmp(token, "SLEEP") == 0) {
    char* arg = strtok(NULL, " ");
    if (!arg) {
      logToSerial("SLEEP", "-", "ERROR", "missing ms");
      return;
    }
    unsigned long ms = atol(arg);
    if (ms > MAX_SLEEP_MS) ms = MAX_SLEEP_MS;
    delay(ms);
    logToSerial("SLEEP", "-", "OK", "slept");
    return;
  }

  // READ/WRITE/APPEND sú zakázané (žiadna SD)
  if (strcmp(token, "READ") == 0 || strcmp(token, "WRITE") == 0 || strcmp(token, "APPEND") == 0) {
    logToSerial(token, "-", "ERROR", "SD card not supported in this mode");
    return;
  }

  if (!authorized) {
    logToSerial("NETCMD", rawline, "SKIPPED", "not in authorized subnet");
    return;
  }

  if (strcmp(token, "PING") == 0) {
    char* target = strtok(NULL, " ");
    if (!target) {
      logToSerial("PING", "-", "ERROR", "missing target");
      return;
    }
    IPAddress ip;
    if (!parseIP(target, ip)) {
      logToSerial("PING", target, "ERROR", "invalid IP");
      return;
    }
    char details[64];
    bool res = safe_tcp_check(ip, 80, TCP_CHECK_TIMEOUT, details, sizeof(details));
    logToSerial("PING", target, res ? "UP" : "DOWN", details);
    return;
  }

  if (strcmp(token, "TCP_CHECK") == 0) {
    char* target = strtok(NULL, " ");
    char* portS = strtok(NULL, " ");
    if (!target || !portS) {
      logToSerial("TCP_CHECK", "-", "ERROR", "missing args");
      return;
    }
    IPAddress ip;
    if (!parseIP(target, ip)) {
      logToSerial("TCP_CHECK", target, "ERROR", "invalid IP");
      return;
    }
    uint16_t port = atoi(portS);
    char details[64];
    bool ok = safe_tcp_check(ip, port, TCP_CHECK_TIMEOUT, details, sizeof(details));
    logToSerial("TCP_CHECK", target, ok ? "OPEN" : "CLOSED", details);
    return;
  }

  if (strcmp(token, "HTTP_HEAD") == 0) {
    char* target = strtok(NULL, " ");
    if (!target) {
      logToSerial("HTTP_HEAD", "-", "ERROR", "missing target");
      return;
    }
    IPAddress ip;
    if (!parseIP(target, ip)) {
      logToSerial("HTTP_HEAD", target, "ERROR", "invalid IP");
      return;
    }
    char summary[160];
    if (safe_http_head(ip, summary, sizeof(summary))) {
      logToSerial("HTTP_HEAD", target, "OK", summary);
    } else {
      logToSerial("HTTP_HEAD", target, "FAIL", summary);
    }
    return;
  }

  logToSerial("UNKNOWN_CMD", rawline, "IGNORED", "not in whitelist");
}
