/* WT32-ETH01 - Test network scanner with safe deauth (test lab only!)
   Serial commands via FTDI/CH340
   LEDs: green = status, orange = error
   SD logging optional
   WARNING: disconnect/deauth works ONLY in test environment you own
*/

#include <Arduino.h>
#include <ETH.h>
#include <SPI.h>
#include <SD.h>
#include <vector>
#include <algorithm>

// ---------- CONFIG ----------
#define LED_GREEN_PIN 2
#define LED_ORANGE_PIN 4
#define SD_CS_PIN 5
bool useSD = true;

#define LED_ON HIGH
#define LED_OFF LOW

String baseSubnet = "192.168.1."; // fallback subnet
volatile bool firstCommandSeen = false;

// Serial buffer
String lineBuf = "";

// ---------- SETUP ----------
void setup() {
  Serial.begin(115200);
  delay(1500);

  pinMode(LED_GREEN_PIN, OUTPUT);
  pinMode(LED_ORANGE_PIN, OUTPUT);
  digitalWrite(LED_GREEN_PIN, LED_OFF);
  digitalWrite(LED_ORANGE_PIN, LED_OFF);

  // Start blink task
  xTaskCreatePinnedToCore(blinkTask, "blinkTask", 2048, NULL, 1, NULL, 1);

  // SD card init
  if (useSD) {
    if (!SD.begin(SD_CS_PIN)) {
      Serial.println("[SD] failed -> disabled");
      useSD = false;
      digitalWrite(LED_ORANGE_PIN, LED_ON);
      delay(200);
      digitalWrite(LED_ORANGE_PIN, LED_OFF);
    } else {
      File f = SD.open("/loot.txt", FILE_APPEND);
      if (f) {
        f.println("=== Session start ===");
        f.close();
      }
    }
  }

  // Start Ethernet
  startEthernet();

  Serial.println("Type 'help' for commands.");
}

// ---------- LOOP ----------
void loop() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      lineBuf.trim();
      if (lineBuf.length() > 0) {
        firstCommandSeen = true;
        parseCommand(lineBuf);
      }
      lineBuf = "";
    } else {
      lineBuf += c;
    }
  }
  delay(10);
}

// ---------- COMMAND PARSER ----------
void parseCommand(String cmd) {
  cmd.toLowerCase();
  int sp = cmd.indexOf(' ');
  String base = (sp == -1) ? cmd : cmd.substring(0, sp);

  if (base == "help") {
    Serial.println("help | info | setsubnet <base> | scan | ports <IP> | host <IP> | disconnect | livetraffic");
    Serial.println("NOTE: 'livetraffic' simulates activity (not real bandwidth).");
  } else if (base == "info") {
    printEthInfo();
  } else if (base == "setsubnet") {
    if (sp == -1) Serial.println("Usage: setsubnet 192.168.1.");
    else {
      baseSubnet = cmd.substring(sp + 1);
      if (!baseSubnet.endsWith(".")) baseSubnet += ".";
      Serial.println("[CONF] baseSubnet=" + baseSubnet);
    }
  } else if (base == "scan") {
    safeScan();
  } else if (base == "ports") {
    if (sp == -1) Serial.println("Usage: ports <IP>");
    else portProbe(cmd.substring(sp + 1));
  } else if (base == "host") {
    if (sp == -1) Serial.println("Usage: host <IP>");
    else reverseDNS(cmd.substring(sp + 1));
  } else if (base == "disconnect") {
    Serial.println("[DISCONNECT] sending test deauth to all except WT32");
    testDeauthAll(); // only in test lab!
  } else if (base == "livetraffic") {
    liveTraffic();
  } else {
    Serial.println("Unknown command");
  }
}

// ---------- ETH ----------
void startEthernet() {
  Serial.println("[ETH] starting...");
  if (!ETH.begin()) {
    Serial.println("[ETH] fail");
    digitalWrite(LED_ORANGE_PIN, LED_ON);
    delay(200);
    digitalWrite(LED_ORANGE_PIN, LED_OFF);
    return;
  }

  // Wait for link
  unsigned long t0 = millis();
  while (!ETH.linkUp() && millis() - t0 < 8000) delay(100);
  if (!ETH.linkUp()) {
    Serial.println("[ETH] no link");
    return;
  }

  // Wait for DHCP
  t0 = millis();
  while (ETH.localIP() == INADDR_NONE && millis() - t0 < 8000) delay(100);

  Serial.println("[ETH] IP: " + ETH.localIP().toString());
  setBaseFromLocalIP();

  // 3 slow green blinks
  for (int i = 0; i < 3; i++) {
    digitalWrite(LED_GREEN_PIN, LED_ON); delay(400);
    digitalWrite(LED_GREEN_PIN, LED_OFF); delay(400);
  }
}

// Set subnet from local IP
void setBaseFromLocalIP() {
  IPAddress ip = ETH.localIP();
  if (ip == INADDR_NONE) return;

  String s = ip.toString();
  int a, b, c, d;
  if (sscanf(s.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
    baseSubnet = String(a) + "." + String(b) + "." + String(c) + ".";
    Serial.println("[CONF] baseSubnet=" + baseSubnet);
  }
}

void printEthInfo() {
  Serial.println("===ETH INFO===");
  Serial.println("IP: " + ETH.localIP().toString());
  Serial.println("MAC: " + ETH.macAddress());
  Serial.println("================");
}

// ---------- SAFE SCAN (ICMP ping) ----------
void safeScan() {
  Serial.println("[SCAN] starting " + baseSubnet + "1..254");
  Serial.println("IP, MAC, HOSTNAME");
  for (int i = 1; i <= 254; i++) {
    String ipStr = baseSubnet + String(i);
    IPAddress ip;
    if (!ip.fromString(ipStr.c_str())) continue;

    if (ETH.ping(ip, 100)) { // 100ms timeout
      String mac = "-"; // ETH doesn't provide remote MAC easily
      String host = "-";
      String out = ipStr + ", " + mac + ", " + host;
      Serial.println(out);
      if (useSD) {
        File f = SD.open("/loot.txt", FILE_APPEND);
        if (f) {
          f.println(out);
          f.close();
        }
      }
    }
    delay(5);
  }
  Serial.println("[SCAN] done");
  // Blink green 2x
  for (int i = 0; i < 2; i++) {
    digitalWrite(LED_GREEN_PIN, LED_ON); delay(200);
    digitalWrite(LED_GREEN_PIN, LED_OFF); delay(200);
  }
}

// ---------- PORT PROBE (placeholder) ----------
void portProbe(String ip) {
  Serial.println("[PORTS] " + ip + " (not implemented)");
}

// ---------- REVERSE DNS (placeholder) ----------
void reverseDNS(String ip) {
  Serial.println("[HOST] " + ip + " -> -");
}

// ---------- DEAUTH TEST FUNCTION (Wi-Fi only – not applicable on ETH) ----------
void testDeauthAll() {
  Serial.println("[DEAUTH] Not supported on Ethernet (Wi-Fi only)");
}

// ---------- LIVE TRAFFIC SIMULATION ----------
void liveTraffic() {
  Serial.println("[LIVETRAFFIC] Scanning for active hosts (simulated by ping speed)...");
  
  struct Host {
    String ip;
    unsigned long rtt; // round-trip time in ms
  };
  std::vector<Host> activeHosts;

  for (int i = 1; i <= 254; i++) {
    String ipStr = baseSubnet + String(i);
    IPAddress ip;
    if (!ip.fromString(ipStr.c_str())) continue;

    // Skip self
    if (ip == ETH.localIP()) continue;

    unsigned long start = millis();
    if (ETH.ping(ip, 150)) { // 150ms timeout
      unsigned long rtt = millis() - start;
      activeHosts.push_back({ipStr, rtt});
    }
    delay(1); // prevent watchdog
  }

  // Sort by RTT (lower = faster = "more active" in simulation)
  std::sort(activeHosts.begin(), activeHosts.end(),
            [](const Host& a, const Host& b) { return a.rtt < b.rtt; });

  Serial.println("Top active hosts (simulated):");
  Serial.println("IP, Response (ms)");
  int count = 0;
  for (const auto& h : activeHosts) {
    if (count >= 5) break;
    Serial.println(h.ip + ", " + String(h.rtt));
    count++;
  }

  if (activeHosts.empty()) {
    Serial.println("No responsive hosts found.");
  }
}

// ---------- BLINK TASK ----------
void blinkTask(void *pvParameters) {
  for (;;) {
    if (!firstCommandSeen) {
      digitalWrite(LED_GREEN_PIN, LED_ON); delay(300);
      digitalWrite(LED_GREEN_PIN, LED_OFF); delay(300);
    } else {
      digitalWrite(LED_GREEN_PIN, LED_OFF);
      vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
  }
}