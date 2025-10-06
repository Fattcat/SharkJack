/* WT32-ETH01 + Wi-Fi AP Control Terminal
   - Wi-Fi AP (no internet bridging!)
   - Web terminal with login
   - Serial control (optional)
   - ONEJOB mode: auto-scan + save to SD
   - Credentials: user / PasSwOORD-1
*/

#define WIFI_ENABLED true        // true = create Wi-Fi AP, false = disable Wi-Fi
#define SERIAL_ENABLED true      // true = allow Serial commands
#define ONEJOB_MODE false        // true = run full scan once on boot, then blink green

#include <Arduino.h>
#include <ETH.h>
#include <SPI.h>
#include <SD.h>

#if WIFI_ENABLED
  #include <WiFi.h>
  #include <WebServer.h>
  WebServer server(80);
#endif

#include <vector>
#include <algorithm>

// ---------- CONFIG ----------
#define LED_GREEN_PIN 2
#define LED_ORANGE_PIN 4
#define SD_CS_PIN 5

#define LED_ON HIGH
#define LED_OFF LOW

String baseSubnet = "192.168.1.";
volatile bool firstCommandSeen = false;
bool useSD = true;

// Credentials
const char* WWW_USERNAME = "user";
const char* WWW_PASSWORD = "PasSwOORD-1";
const char* SESSION_TOKEN = "AUTH_TOKEN_12345"; // simple token for demo

#if WIFI_ENABLED
String currentSession = "";
#endif

// ---------- SETUP ----------
void setup() {
  Serial.begin(115200);
  delay(1000);

  pinMode(LED_GREEN_PIN, OUTPUT);
  pinMode(LED_ORANGE_PIN, OUTPUT);
  digitalWrite(LED_GREEN_PIN, LED_OFF);
  digitalWrite(LED_ORANGE_PIN, LED_OFF);

  // SD init
  if (useSD) {
    if (!SD.begin(SD_CS_PIN)) {
      Serial.println("[SD] failed");
      useSD = false;
      blinkError();
    } else {
      File f = SD.open("/loot.txt", FILE_APPEND);
      if (f) { f.println("=== NEW SESSION ==="); f.close(); }
    }
  }

  // Ethernet
  startEthernet();

#if WIFI_ENABLED
  startWiFiAP();
  setupWebServer();
#endif

#if SERIAL_ENABLED
  Serial.println("Serial control enabled. Type 'help' for commands.");
#endif

#if ONEJOB_MODE
  Serial.println("[ONEJOB] Starting full network scan...");
  runOneJob();
  // After success, blink green forever
  while (true) {
    digitalWrite(LED_GREEN_PIN, LED_ON); delay(500);
    digitalWrite(LED_GREEN_PIN, LED_OFF); delay(500);
  }
#endif
}

// ---------- LOOP ----------
void loop() {
#if SERIAL_ENABLED
  handleSerial();
#endif

#if WIFI_ENABLED
  server.handleClient();
#endif

  delay(10);
}

// ==================== ETHERNET ====================
void startEthernet() {
  Serial.println("[ETH] Starting...");
  if (!ETH.begin()) {
    Serial.println("[ETH] Failed");
    blinkError();
    return;
  }

  unsigned long t0 = millis();
  while (!ETH.linkUp() && millis() - t0 < 8000) delay(100);
  if (!ETH.linkUp()) {
    Serial.println("[ETH] No link");
    return;
  }

  t0 = millis();
  while (ETH.localIP() == INADDR_NONE && millis() - t0 < 8000) delay(100);

  Serial.println("[ETH] IP: " + ETH.localIP().toString());
  setBaseFromLocalIP();
}

void setBaseFromLocalIP() {
  IPAddress ip = ETH.localIP();
  if (ip == INADDR_NONE) return;
  String s = ip.toString();
  int a, b, c, d;
  if (sscanf(s.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
    baseSubnet = String(a) + "." + String(b) + "." + String(c) + ".";
  }
}

// ==================== SERIAL ====================
String lineBuf = "";
void handleSerial() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      lineBuf.trim();
      if (lineBuf.length() > 0) {
        firstCommandSeen = true;
        executeCommand(lineBuf, true); // true = from serial
      }
      lineBuf = "";
    } else {
      lineBuf += c;
    }
  }
}

// ==================== COMMAND EXECUTION ====================
String executeCommand(String cmd, bool logToSD = false) {
  cmd.toLowerCase();
  int sp = cmd.indexOf(' ');
  String base = (sp == -1) ? cmd : cmd.substring(0, sp);
  String output = "";

  if (base == "help") {
    output = "help | info | setsubnet <base> | scan | ports <IP> | host <IP> | livetraffic";
  } else if (base == "info") {
    output = "IP: " + ETH.localIP().toString() + "\nMAC: " + ETH.macAddress();
  } else if (base == "setsubnet") {
    if (sp == -1) output = "Usage: setsubnet 192.168.1.";
    else {
      baseSubnet = cmd.substring(sp + 1);
      if (!baseSubnet.endsWith(".")) baseSubnet += ".";
      output = "[CONF] baseSubnet=" + baseSubnet;
    }
  } else if (base == "scan") {
    output = runScan();
  } else if (base == "ports") {
    if (sp == -1) output = "Usage: ports <IP>";
    else output = runPortScan(cmd.substring(sp + 1));
  } else if (base == "host") {
    output = "[HOST] Not implemented";
  } else if (base == "livetraffic") {
    output = runLiveTraffic();
  } else {
    output = "Unknown command";
  }

  if (logToSD && useSD) {
    File f = SD.open("/loot.txt", FILE_APPEND);
    if (f) {
      f.println("CMD: " + cmd);
      f.println("OUT: " + output);
      f.println("---");
      f.close();
    }
  }

  return output;
}

// ==================== ONEJOB MODE ====================
void runOneJob() {
  String fullLog = "";
  fullLog += "=== FULL SCAN START ===\n";

  // Scan all IPs
  String scanResult = runScan();
  fullLog += "SCAN:\n" + scanResult + "\n";

  // Extract IPs and scan top 5 ports
  std::vector<String> ips;
  int start = 0;
  while ((start = scanResult.indexOf('\n', start)) != -1) {
    int end = scanResult.indexOf(',', start);
    if (end != -1) {
      String ip = scanResult.substring(start + 1, end);
      if (ip.length() > 6) ips.push_back(ip);
    }
    start++;
    if (ips.size() >= 5) break;
  }

  for (String ip : ips) {
    fullLog += "PORTS " + ip + ":\n" + runPortScan(ip) + "\n";
  }

  fullLog += "=== FULL SCAN END ===\n";

  if (useSD) {
    File f = SD.open("/loot.txt", FILE_APPEND);
    if (f) {
      f.print(fullLog);
      f.close();
      Serial.println("[ONEJOB] Results saved to /loot.txt");
    }
  }

  // Blink green to signal success
  for (int i = 0; i < 5; i++) {
    digitalWrite(LED_GREEN_PIN, LED_ON); delay(200);
    digitalWrite(LED_GREEN_PIN, LED_OFF); delay(200);
  }
}

// ==================== SCAN FUNCTIONS ====================
String runScan() {
  String out = "";
  for (int i = 1; i <= 254; i++) {
    String ipStr = baseSubnet + String(i);
    IPAddress ip;
    if (!ip.fromString(ipStr.c_str())) continue;
    if (ip == ETH.localIP()) continue;

    if (ETH.ping(ip, 100)) {
      out += ipStr + ", -, -\n";
    }
    delay(1);
  }
  if (out == "") out = "No hosts found.";
  return out;
}

String runPortScan(String ip) {
  String out = "";
  int commonPorts[] = {21, 22, 23, 80, 443, 8080};
  for (int p : commonPorts) {
    WiFiClient client;
    if (client.connect(ip.c_str(), p, 200)) { // 200ms timeout
      out += String(p) + "/open\n";
      client.stop();
    }
    delay(1);
  }
  if (out == "") out = "No open ports (21,22,23,80,443,8080).";
  return out;
}

String runLiveTraffic() {
  struct Host { String ip; unsigned long rtt; };
  std::vector<Host> hosts;
  for (int i = 1; i <= 254; i++) {
    String ipStr = baseSubnet + String(i);
    IPAddress ip;
    if (!ip.fromString(ipStr.c_str())) continue;
    if (ip == ETH.localIP()) continue;
    unsigned long t0 = millis();
    if (ETH.ping(ip, 150)) {
      hosts.push_back({ipStr, millis() - t0});
    }
    delay(1);
  }
  std::sort(hosts.begin(), hosts.end(), [](auto& a, auto& b) { return a.rtt < b.rtt; });
  String out = "";
  for (int i = 0; i < 5 && i < hosts.size(); i++) {
    out += hosts[i].ip + " (" + String(hosts[i].rtt) + "ms)\n";
  }
  if (out == "") out = "No active hosts.";
  return out;
}

// ==================== WIFI AP & WEB SERVER ====================
#if WIFI_ENABLED
void startWiFiAP() {
  WiFi.mode(WIFI_AP);
  WiFi.softAP("WT32-Control", nullptr); // no password for AP (login via web)
  Serial.println("[WIFI] AP started: WT32-Control");
}

void setupWebServer() {
  server.on("/", HTTP_GET, []() {
    if (isAuthenticated()) {
      sendTerminalPage();
    } else {
      sendLoginPage();
    }
  });

  server.on("/login", HTTP_POST, []() {
    String user = server.arg("user");
    String pass = server.arg("pass");
    if (user == WWW_USERNAME && pass == WWW_PASSWORD) {
      currentSession = SESSION_TOKEN;
      server.sendHeader("Set-Cookie", "auth=" + currentSession);
      server.send(200, "text/plain", "OK");
    } else {
      server.send(401, "text/plain", "Invalid credentials");
    }
  });

  server.on("/cmd", HTTP_POST, []() {
    if (!isAuthenticated()) {
      server.send(403, "text/plain", "Unauthorized");
      return;
    }
    String cmd = server.arg("cmd");
    String result = executeCommand(cmd, true);
    server.send(200, "text/plain", result);
  });

  server.begin();
}

bool isAuthenticated() {
  String cookie = server.header("Cookie");
  return cookie.indexOf("auth=" + String(SESSION_TOKEN)) != -1;
}

void sendLoginPage() {
  String html = R"rawliteral(
<!DOCTYPE html>
<html>
<head><title>WT32 Login</title>
<style>
body{font-family:sans-serif;background:#f0f0f0;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.card{background:white;padding:2rem;border-radius:10px;box-shadow:0 4px 12px rgba(0,0,0,0.1)}
input{width:100%;padding:0.5rem;margin:0.5rem 0;border:1px solid #ccc;border-radius:4px}
button{background:#4CAF50;color:white;padding:0.6rem;width:100%;border:none;border-radius:4px;cursor:pointer}
</style>
</head>
<body>
<div class="card">
  <h2>WT32 Control</h2>
  <form id="login">
    <input type="text" id="user" placeholder="Username" required>
    <input type="password" id="pass" placeholder="Password" required>
    <button type="submit">Login</button>
  </form>
  <p id="msg" style="color:red"></p>
</div>
<script>
document.getElementById('login').onsubmit = async e => {
  e.preventDefault();
  const res = await fetch('/login', {
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body: 'user='+encodeURIComponent(document.getElementById('user').value)+
          '&pass='+encodeURIComponent(document.getElementById('pass').value)
  });
  if(res.ok) window.location='/';
  else document.getElementById('msg').innerText = 'Login failed';
};
</script>
</body>
</html>
)rawliteral";
  server.send(200, "text/html", html);
}

void sendTerminalPage() {
  String html = R"rawliteral(
<!DOCTYPE html>
<html>
<head><title>WT32 Terminal</title>
<style>
body{font-family:monospace;background:#0d0d0d;color:#0f0;margin:0;padding:1rem}
#output{width:100%;height:70vh;background:#000;color:#0f0;padding:1rem;overflow:auto;border:1px solid #0f0}
#cmd{width:100%;padding:0.5rem;background:#000;color:#0f0;border:1px solid #0f0}
button{margin-top:0.5rem;background:#0f0;color:#000;border:none;padding:0.5rem;cursor:pointer}
</style>
</head>
<body>
<h2>WT32 Control Terminal</h2>
<textarea id="output" readonly></textarea><br>
<input type="text" id="cmd" placeholder="Enter command (help for list)">
<button onclick="sendCmd()">Send</button>
<button onclick="location.reload()">Logout</button>

<script>
const output = document.getElementById('output');
const cmd = document.getElementById('cmd');

function append(text) {
  output.value += text + '\n';
  output.scrollTop = output.scrollHeight;
}

async function sendCmd() {
  const command = cmd.value.trim();
  if (!command) return;
  append('$ ' + command);
  cmd.value = '';
  try {
    const res = await fetch('/cmd', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: 'cmd=' + encodeURIComponent(command)
    });
    const text = await res.text();
    append(text);
  } catch (e) {
    append('Error: ' + e.message);
  }
}

// Load help on start
window.onload = () => {
  append('Connected. Type "help" for commands.');
};
</script>
</body>
</html>
)rawliteral";
  server.send(200, "text/html", html);
}
#endif

// ==================== UTILS ====================
void blinkError() {
  for (int i = 0; i < 3; i++) {
    digitalWrite(LED_ORANGE_PIN, LED_ON); delay(200);
    digitalWrite(LED_ORANGE_PIN, LED_OFF); delay(200);
  }
}