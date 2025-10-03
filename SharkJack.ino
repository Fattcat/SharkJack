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

// Konfigurácia autorizovaného subnetu (jednoduché checkovanie prefixu 192.168.1.x)
const uint8_t AUTH_PREFIX[3] = {192, 168, 1}; // povolený prefix (3 oktety)
const int AUTH_PREFIX_LEN = 3;
const int MAX_CIDR_SIZE = 32; // nevyužívame veľké CIDR v tomto sketchi

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

// MAC pre Ethernet (upraviť ak potrebuješ unikátnu MAC)
byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };

void setup() {
  Serial.begin(115200);
  while (!Serial) { ; }

  // Nastav CS pini ako OUTPUT a deselect
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
  Serial.print("IP: "); Serial.println(myIP);

  // Inicializuj SD
  Serial.println("Initializing SD...");
  // SD.begin will pull CS low internally, ensure we set it correctly afterwards
  if (!SD.begin(CS_SD)) {
    Serial.println("SD init failed! Check wiring and 3.3V power.");
    // pokračujeme, ale bez SD nie je možné spracovať payload
  } else {
    Serial.println("SD initialized.");
    processPayloadFile();
  }

  Serial.println("Setup complete.");
}

void loop() {
  // nič opakovane nerobíme; payload je jednorázovo spracovaný pri štarte
  delay(60000);
}

// ================= helpery =================

unsigned long now_ms() {
  return millis();
}

void appendLoot(const char* tag, const char* target, const char* result, const char* details) {
  // zapíše do loot.txt jeden riadok v tvare:
  // <millis> | <TAG> | <TARGET> | <RESULT> | <DETAILS>
  if (!SD.exists("loot.txt")) {
    File f = SD.open("loot.txt", FILE_WRITE);
    if (f) f.close();
  }
  File out = SD.open("loot.txt", FILE_WRITE);
  if (!out) {
    Serial.println("Failed to open loot.txt for append.");
    return;
  }
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

// overí, či IP adresa začína autorizovaným prefixom (len pre IPv4)
bool inAuthorizedSubnet(IPAddress ip) {
  // porovnaj prvé 3 oktety
  for (int i=0;i<AUTH_PREFIX_LEN;i++) {
    if (ip[i] != AUTH_PREFIX[i]) return false;
  }
  return true;
}

bool portAllowed(uint16_t p) {
  for (size_t i=0;i<ALLOWED_PORTS_COUNT;i++) if (ALLOWED_PORTS[i]==p) return true;
  return false;
}

// jednoduchý parser IP z textu "a.b.c.d"
bool parseIP(const char* s, IPAddress &out) {
  int parts[4] = {0,0,0,0};
  int idx = 0;
  const char* p = s;
  char num[4];
  int nidx = 0;
  int part = 0;
  while (*p && part<4) {
    if (*p=='.') {
      num[nidx]=0; parts[part++] = atoi(num); nidx=0;
    } else {
      if (nidx<3) num[nidx++] = *p;
    }
    p++;
  }
  if (nidx>0 && part<4) { num[nidx]=0; parts[part++]=atoi(num); }
  if (part!=4) return false;
  for (int i=0;i<4;i++) if (parts[i]<0 || parts[i]>255) return false;
  out = IPAddress(parts[0],parts[1],parts[2],parts[3]);
  return true;
}

// ================= sieťové operácie (bezpečné) =================

// TCP_CHECK: pokus o krátke TCP pripojenie (len overí connect), timeout v ms
bool safe_tcp_check(const IPAddress &ip, uint16_t port, unsigned long timeout, char* out_details, size_t details_len) {
  if (!portAllowed(port)) {
    strncpy(out_details, "PORT_NOT_ALLOWED", details_len-1);
    out_details[details_len-1]=0;
    return false;
  }
  EthernetClient client;
  unsigned long start = now_ms();
  bool ok = client.connect(ip, port);
  while (!ok && (now_ms()-start) < timeout) {
    // krátke opakovanie
    delay(5);
    ok = client.connect(ip, port);
  }
  if (ok) {
    client.stop();
    strncpy(out_details, "OPEN", details_len-1); out_details[details_len-1]=0;
    return true;
  } else {
    strncpy(out_details, "CLOSED_TIMEOUT", details_len-1); out_details[details_len-1]=0;
    return false;
  }
}

// HTTP_HEAD: odoslanie jednoduchého HEAD požiadavku na port 80 (timeout)
bool safe_http_head(const IPAddress &ip, char* out_summary, size_t sum_len) {
  const uint16_t port = 80;
  if (!portAllowed(port)) {
    strncpy(out_summary, "PORT_NOT_ALLOWED", sum_len-1); out_summary[sum_len-1]=0;
    return false;
  }
  EthernetClient client;
  unsigned long start = now_ms();
  if (!client.connect(ip, port)) {
    // pokúsime sa ešte krátko
    while ((now_ms()-start) < HTTP_HEAD_TIMEOUT) {
      delay(5);
      if (client.connect(ip, port)) break;
    }
  }
  if (!client.connected()) {
    strncpy(out_summary, "CONNECT_FAIL", sum_len-1); out_summary[sum_len-1]=0;
    client.stop();
    return false;
  }
  // POST-HTTP HEAD request
  client.print("HEAD / HTTP/1.0\r\nHost: ");
  client.print(ip);
  client.print("\r\nConnection: close\r\n\r\n");

  // čítaj ako text, skúsme získať status line a Server header (dočasne)
  unsigned long tstart = now_ms();
  bool gotStatus = false;
  char serverHdr[80]; serverHdr[0]=0;
  char statusLine[80]; statusLine[0]=0;

  String line;
  while (client.connected() && (now_ms()-tstart) < HTTP_HEAD_TIMEOUT) {
    if (client.available()) {
      line = client.readStringUntil('\n');
      line.trim();
      if (!gotStatus) {
        line.toCharArray(statusLine, sizeof(statusLine));
        gotStatus = true;
      }
      // hľadaj Server: header
      if (line.startsWith("Server:")) {
        line.substring(7).trim().toCharArray(serverHdr, sizeof(serverHdr));
      }
      // ak sme prečítali prázdny riadok, skonči (end of headers)
      if (line.length()==0) break;
    }
  }
  client.stop();
  if (!gotStatus) {
    strncpy(out_summary, "NO_STATUS", sum_len-1); out_summary[sum_len-1]=0;
    return false;
  }
  // zostav summary
  if (serverHdr[0]!=0) {
    snprintf(out_summary, sum_len, "STATUS:%s;SERVER:%s", statusLine, serverHdr);
  } else {
    snprintf(out_summary, sum_len, "STATUS:%s", statusLine);
  }
  return true;
}

// ================= parsovanie a vykonanie príkazu =================

void processPayloadFile() {
  if (!SD.exists("LANpayload.txt")) {
    Serial.println("No LANpayload.txt present on SD.");
    appendLoot("INFO","LANpayload.txt","MISSING","LANpayload.txt not found");
    return;
  }
  File f = SD.open("LANpayload.txt", FILE_READ);
  if (!f) {
    Serial.println("Failed to open LANpayload.txt");
    appendLoot("ERROR","LANpayload.txt","OPEN_FAIL","Cannot open file");
    return;
  }

  IPAddress myIP = Ethernet.localIP();
  bool authorized = inAuthorizedSubnet(myIP);
  if (!authorized) {
    Serial.println("Not in authorized subnet -> network commands will be skipped.");
    appendLoot("AUTH","NETWORK","DENIED","Device not in authorized subnet");
  }

  // read line by line
  size_t idx=0;
  while (f.available()) {
    char c = f.read();
    if (c == '\r') continue;
    if (c == '\n' || idx >= LINE_BUF-1) {
      linebuf[idx]=0;
      idx=0;
      // spracuj riadok
      if (strlen(linebuf)>0) handleCommandLine(linebuf, authorized);
      linebuf[0]=0;
    } else {
      linebuf[idx++]=c;
    }
  }
  // posledný riadok bez newline
  if (idx>0) {
    linebuf[idx]=0;
    handleCommandLine(linebuf, authorized);
  }

  f.close();
  Serial.println("Finished processing LANpayload.txt");
}

void trim_leadtrail(char* s) {
  // odstráni lead/trailing spaces
  // leading
  int i=0; while (s[i]==' '||s[i]=='\t') i++;
  if (i>0) memmove(s, s+i, strlen(s+i)+1);
  // trailing
  int len = strlen(s);
  while (len>0 && (s[len-1]==' '||s[len-1]=='\t')) s[--len]=0;
}

void handleCommandLine(char* rawline, bool authorized) {
  trim_leadtrail(rawline);
  if (rawline[0]==0) return;
  if (rawline[0]=='#') return; // comment
  // remove trailing ; if exist
  int rl = strlen(rawline);
  if (rawline[rl-1]==';') rawline[rl-1]=0;

  // tokenizuj
  char copyLine[LINE_BUF+1];
  strncpy(copyLine, rawline, LINE_BUF);
  copyLine[LINE_BUF]=0;

  char *token = strtok(copyLine, " ");
  if (!token) return;
  // uppercase command for comparison
  for (char* p=token; *p; ++p) if (*p>='a' && *p<='z') *p = *p - 'a' + 'A';

  if (strcmp(token, "NOP")==0) {
    appendLoot("NOP","-","OK","NOP executed");
    return;
  }

  if (strcmp(token, "SLEEP")==0) {
    char* arg = strtok(NULL, " ");
    if (!arg) { appendLoot("SLEEP","-","BAD_PARAM","missing ms"); return; }
    unsigned long ms = atol(arg);
    if (ms > MAX_SLEEP_MS) ms = MAX_SLEEP_MS;
    delay(ms);
    appendLoot("SLEEP","-","OK","slept");
    return;
  }

  if (strcmp(token, "READ")==0) {
    char* fname = strtok(NULL, " ");
    if (!fname) { appendLoot("READ","-","BAD_PARAM","missing filename"); return; }
    // safe: only simple filename (no path)
    trim_leadtrail(fname);
    File in = SD.open(fname, FILE_READ);
    if (!in) {
      appendLoot("READ", fname, "OPEN_FAIL", "cannot open");
      return;
    }
    // čítaj po riadkoch a zapisuj do loot.txt s tag READLINE
    char rline[120];
    size_t ridx=0;
    while (in.available()) {
      char ch = in.read();
      if (ch=='\r') continue;
      if (ch=='\n' || ridx>=sizeof(rline)-2) {
        rline[ridx]=0;
        appendLoot("READLINE", fname, "OK", rline);
        ridx=0;
      } else rline[ridx++]=ch;
    }
    if (ridx>0) { rline[ridx]=0; appendLoot("READLINE", fname, "OK", rline); }
    in.close();
    appendLoot("READ", fname, "DONE", "read complete");
    return;
  }

  if (strcmp(token, "WRITE")==0 || strcmp(token,"APPEND")==0) {
    char* fname = strtok(NULL, " ");
    char* rest = strtok(NULL, ""); // zvyšok (možno s úvodzovkami)
    if (!fname || !rest) { appendLoot(token, "-", "BAD_PARAM", "missing args"); return; }
    trim_leadtrail(rest);
    // očisti úvodzovky
    if (rest[0]=='"') {
      size_t l = strlen(rest);
      if (rest[l-1]=='"') {
        rest[l-1]=0;
        rest++;
      } // inak bereme ako celé zvyšné
    }
    // safe: open file
    File fo = SD.open(fname, FILE_WRITE);
    if (!fo) { appendLoot(token, fname, "OPEN_FAIL","cannot open"); return; }
    if (strcmp(token,"WRITE")==0) {
      fo.seek(0); // prepíše
      fo.print(rest);
    } else {
      fo.println(rest);
    }
    fo.close();
    appendLoot(token, fname, "OK", rest);
    return;
  }

  // NETWORK commands require authorization
  if (!authorized) {
    appendLoot("NETCMD", rawline, "SKIPPED", "not in authorized subnet");
    return;
  }

  if (strcmp(token, "PING")==0) {
    // Implementované ako TCP_CHECK na port 80: len jednoduchý reachability check
    char* target = strtok(NULL, " ");
    if (!target) { appendLoot("PING","-","BAD_PARAM","missing target"); return; }
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

  if (strcmp(token, "TCP_CHECK")==0) {
    char* target = strtok(NULL, " ");
    char* portS = strtok(NULL, " ");
    if (!target || !portS) { appendLoot("TCP_CHECK","-","BAD_PARAM","missing args"); return; }
    IPAddress ip;
    if (!parseIP(target, ip)) { appendLoot("TCP_CHECK", target, "BAD_PARAM","invalid ip"); return; }
    uint16_t port = atoi(portS);
    char details[64];
    bool ok = safe_tcp_check(ip, port, TCP_CHECK_TIMEOUT, details, sizeof(details));
    appendLoot("TCP_CHECK", target, ok ? "OPEN" : "CLOSED", details);
    return;
  }

  if (strcmp(token, "HTTP_HEAD")==0) {
    char* target = strtok(NULL, " ");
    if (!target) { appendLoot("HTTP_HEAD","-","BAD_PARAM","missing target"); return; }
    IPAddress ip;
    if (!parseIP(target, ip)) { appendLoot("HTTP_HEAD", target, "BAD_PARAM","invalid ip"); return; }
    char summary[160];
    if (safe_http_head(ip, summary, sizeof(summary))) {
      appendLoot("HTTP_HEAD", target, "OK", summary);
    } else {
      appendLoot("HTTP_HEAD", target, "FAIL", summary);
    }
    return;
  }

  // unknown
  appendLoot("UNKNOWN_CMD", rawline, "IGNORED", "not in whitelist");
}
