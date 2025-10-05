/*
  Arduino Nano + ENC28J60 – Stabilný sieťový scanner
  Opravená inicializácia, fallback IP, overenie spojenia
*/

#include <SPI.h>
#include <UIPEthernet.h>

#define CS_ENC 10
#define LED_PIN 13

byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };

// Bežné porty
const uint16_t COMMON_PORTS[] = {21,22,23,25,53,80,110,135,139,443,445,3306,3389,5900};
const size_t PORT_COUNT = sizeof(COMMON_PORTS) / sizeof(COMMON_PORTS[0]);

bool ethReady = false;
bool started = false;
IPAddress activeIPs[15];
uint8_t activeCount = 0;
IPAddress scanStartIP, scanEndIP;

// Pomocná funkcia: tlač IP bez chyby
void printIP(const IPAddress& ip) {
  for (int i = 0; i < 4; i++) {
    Serial.print(ip[i]);
    if (i < 3) Serial.print(".");
  }
}

// ================= SETUP =================
void setup() {
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  
  // Explicitne nastav CS ako výstup a deaktivuj
  pinMode(CS_ENC, OUTPUT);
  digitalWrite(CS_ENC, HIGH);

  Serial.begin(115200);
  delay(500); // čas na otvorenie Serialu

  Serial.println("\n=== ENC28J60 Network Scanner ===");
  Serial.println("Initializing SPI...");
  SPI.begin();

  Serial.println("Configuring ENC28J60 CS pin...");
  Ethernet.init(CS_ENC);

  // Skús DHCP
  Serial.println("Trying DHCP (10 sec timeout)...");
  byte dhcpResult = Ethernet.begin(mac);
  
  IPAddress myIP;
  if (dhcpResult == 1) {
    myIP = Ethernet.localIP();
    Serial.print("✅ DHCP success. IP: ");
    printIP(myIP);
    Serial.println();
  } else {
    Serial.println("❌ DHCP failed. Using static IP 192.168.1.200");
    myIP = IPAddress(192, 168, 1, 200);
    // DÔLEŽITÉ: zavolaj Ethernet.begin s IP explicitne
    Ethernet.begin(mac, myIP);
    delay(500); // čas na inicializáciu
    // Over, že IP bola nastavená
    myIP = Ethernet.localIP();
    Serial.print("Assigned static IP: ");
    printIP(myIP);
    Serial.println();
  }

  // Over, že IP je platná (nie 0.0.0.0)
  if (myIP[0] != 0) {
    ethReady = true;
    determineScanRange(myIP);
  } else {
    ethReady = false;
    Serial.println("❗ ERROR: Failed to assign any IP!");
  }

  Serial.println("\nType 'start' to begin.");
}

// ================= Určenie rozsahu =================
void determineScanRange(IPAddress ip) {
  uint8_t a = ip[0], b = ip[1];
  if (a == 10) {
    scanStartIP = IPAddress(10, ip[1], ip[2], 1);
    scanEndIP = IPAddress(10, ip[1], ip[2], 30);
  } else if (a == 172 && b >= 16 && b <= 31) {
    scanStartIP = IPAddress(172, b, ip[2], 1);
    scanEndIP = IPAddress(172, b, ip[2], 30);
  } else if (a == 192 && b == 168) {
    scanStartIP = IPAddress(192, 168, b, 1);
    scanEndIP = IPAddress(192, 168, b, 30);
  } else {
    // Fallback na 192.168.1.x
    scanStartIP = IPAddress(192, 168, 1, 1);
    scanEndIP = IPAddress(192, 168, 1, 30);
  }
  Serial.print("🔍 Scan range: ");
  printIP(scanStartIP);
  Serial.print(" – ");
  printIP(scanEndIP);
  Serial.println();
}

// ================= LOOP =================
void loop() {
  static unsigned long lastBlink = 0;
  if (ethReady && millis() - lastBlink >= 500) {
    digitalWrite(LED_PIN, !digitalRead(LED_PIN));
    lastBlink = millis();
  }

  if (Serial.available()) {
    String input = Serial.readStringUntil('\n');
    input.trim();

    if (input.length() == 0) {
      if (!started) Serial.println("waiting for command ...");
      return;
    }

    if (!started) {
      if (input.equalsIgnoreCase("start")) {
        started = true;
        Serial.println("✅ Ready. Commands: SCAN, PORTS");
      } else {
        Serial.println("bad input command");
      }
      return;
    }

    if (input.equalsIgnoreCase("SCAN")) {
      doScan();
    } else if (input.equalsIgnoreCase("PORTS")) {
      doPortScan();
    } else {
      Serial.println("Unknown command. Use: SCAN, PORTS");
    }
  }
}

// ================= Sieťové funkcie =================
bool isHostAlive(IPAddress ip) {
  EthernetClient c;
  if (c.connect(ip, 80)) { c.stop(); return true; }
  c = EthernetClient();
  if (c.connect(ip, 443)) { c.stop(); return true; }
  return false;
}

bool isPortOpen(IPAddress ip, uint16_t port) {
  EthernetClient client;
  unsigned long start = millis();
  if (client.connect(ip, port)) {
    client.stop();
    return true;
  }
  while (millis() - start < 200) {
    if (client.connect(ip, port)) {
      client.stop();
      return true;
    }
    delay(2);
  }
  return false;
}

void doScan() {
  if (!ethReady) {
    Serial.println("❌ Ethernet not ready!");
    return;
  }

  Serial.println("\n🔍 Scanning...");
  activeCount = 0;

  uint32_t start = (uint32_t)scanStartIP;
  uint32_t end = (uint32_t)scanEndIP;

  for (uint32_t addr = start; addr <= end && activeCount < 15; addr++) {
    IPAddress ip(
      (addr >> 24) & 0xFF,
      (addr >> 16) & 0xFF,
      (addr >> 8) & 0xFF,
      addr & 0xFF
    );

    if (ip == Ethernet.localIP()) continue;

    Serial.print("Pinging ");
    printIP(ip);
    Serial.print(" ... ");

    bool alive = isHostAlive(ip);
    if (alive) {
      activeIPs[activeCount++] = ip;
      Serial.println("✅");
    } else {
      Serial.println("❌");
    }
    delay(20); // stabilnejšie pre ENC28J60
  }

  Serial.println("\n📊 Found:");
  for (int i = 0; i < activeCount; i++) {
    printIP(activeIPs[i]);
    Serial.println();
  }
}

void doPortScan() {
  if (activeCount == 0) {
    Serial.println("⚠️ Run 'SCAN' first.");
    return;
  }

  Serial.println("\n📡 Port scan:");
  for (int i = 0; i < activeCount; i++) {
    IPAddress ip = activeIPs[i];
    Serial.print("→ ");
    printIP(ip);
    Serial.print(": ");

    bool found = false;
    for (size_t p = 0; p < PORT_COUNT; p++) {
      if (isPortOpen(ip, COMMON_PORTS[p])) {
        if (found) Serial.print(", ");
        Serial.print(COMMON_PORTS[p]);
        found = true;
        delay(10);
      }
    }
    if (!found) Serial.print("none");
    Serial.println();
  }
  Serial.println("✅ Done.");
}
