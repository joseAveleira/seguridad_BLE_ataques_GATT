/*
 * ESP32 BLE Central - Master Controller
 * 
 * Controla dos periféricos:
 * - ESP32_P1: Sin autenticación
 * - ESP32_P2: Con PIN (vulnerable)
 * 
 * Demuestra:
 * - Conexión a múltiples dispositivos
 * - Autenticación con PIN en texto claro
 * - Envío de comandos de configuración y eventos
 */

#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

// UUIDs para P1
#define P1_SERVICE_UUID     "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define P1_CMD_UUID         "beb5483e-36e1-4688-b7f5-ea07361b26a8"
#define P1_STATE_UUID       "beb5483f-36e1-4688-b7f5-ea07361b26a8"

// UUIDs para P2
#define P2_SERVICE_UUID     "5fafc301-2fb5-459e-8fcc-c5c9c331915c"
#define P2_CMD_UUID         "ceb5483e-46e1-4688-b7f5-ea07361b27a9"
#define P2_STATE_UUID       "ceb5483f-46e1-4688-b7f5-ea07361b27a9"

#define P2_PIN "123456"  // ⚠️ PIN en texto claro visible en código

BLEClient* pClientP1 = nullptr;
BLEClient* pClientP2 = nullptr;
BLERemoteCharacteristic* pP1CmdChar = nullptr;
BLERemoteCharacteristic* pP2CmdChar = nullptr;
bool p1Connected = false;
bool p2Connected = false;

BLEAdvertisedDevice* p1Device = nullptr;
BLEAdvertisedDevice* p2Device = nullptr;

unsigned long lastP1Command = 0;
unsigned long lastP2Command = 0;

void logEvent(const char* device, const char* category, const char* message) {
  Serial.printf("[%08lu] [%s-%s] %s\n", millis(), device, category, message);
}

// Callback de notificaciones P1
void p1NotifyCallback(BLERemoteCharacteristic* pChar, uint8_t* pData, size_t length, bool isNotify) {
  char hexStr[64] = "";
  for (size_t i = 0; i < length; i++) {
    char temp[8];
    sprintf(temp, "%02X ", pData[i]);
    strcat(hexStr, temp);
  }
  char msg[128];
  sprintf(msg, "Notification: [%s]", hexStr);
  logEvent("P1", "RX", msg);
}

// Callback de notificaciones P2
void p2NotifyCallback(BLERemoteCharacteristic* pChar, uint8_t* pData, size_t length, bool isNotify) {
  char hexStr[64] = "";
  for (size_t i = 0; i < length; i++) {
    char temp[8];
    sprintf(temp, "%02X ", pData[i]);
    strcat(hexStr, temp);
  }
  
  // Detectar respuesta de autenticación
  if (pData[0] == 0x01) {
    if (length > 1 && pData[1] == 0x01) {
      logEvent("P2", "AUTH", "✅ Authentication successful!");
    } else {
      logEvent("P2", "AUTH", "❌ Authentication failed!");
    }
  }
  // Decodificar telemetría (0xA0)
  else if (pData[0] == 0xA0 && length > 1) {
    uint8_t telemetryType = pData[1];
    char telemetryMsg[128];
    
    switch (telemetryType) {
      case 0x01: // Vitales
        if (length >= 5) {
          int16_t temp = (pData[2] << 8) | pData[3];
          uint8_t hr = pData[4];
          sprintf(telemetryMsg, "📊 VITALS: Temp=%.1f°C, HR=%d bpm", temp / 10.0, hr);
          logEvent("P2", "TELEM", telemetryMsg);
        }
        break;
        
      case 0x02: // Actividad
        if (length >= 5) {
          uint16_t steps = (pData[2] << 8) | pData[3];
          uint8_t battery = pData[4];
          sprintf(telemetryMsg, "🏃 ACTIVITY: Steps=%d, Battery=%d%%", steps, battery);
          logEvent("P2", "TELEM", telemetryMsg);
        }
        break;
        
      case 0x03: // GPS
        if (length >= 6) {
          int16_t lat = (pData[2] << 8) | pData[3];
          int16_t lon = (pData[4] << 8) | pData[5];
          sprintf(telemetryMsg, "📍 GPS: Lat=%.2f, Lon=%.2f", lat / 100.0, lon / 100.0);
          logEvent("P2", "TELEM", telemetryMsg);
        }
        break;
    }
    return; // No mostrar hex para telemetría
  }
  
  char msg[128];
  sprintf(msg, "Notification: [%s]", hexStr);
  logEvent("P2", "RX", msg);
}

// Enviar comando a P1 (formato antiguo - 4 bytes fijos)
void sendCommandP1(uint8_t cmd, uint8_t param1 = 0, uint8_t param2 = 0, uint8_t param3 = 0) {
  if (!p1Connected || !pP1CmdChar) return;
  
  uint8_t data[4] = {cmd, param1, param2, param3};
  pP1CmdChar->writeValue(data, 4);
  
  char msg[64];
  sprintf(msg, "CMD sent: [%02X %02X %02X %02X]", data[0], data[1], data[2], data[3]);
  logEvent("P1", "TX", msg);
}

// Enviar comando a P2 (formato nuevo - CMD+LEN+DATA)
void sendCommandP2(uint8_t cmd, uint8_t* payload, uint8_t payloadLen) {
  if (!p2Connected || !pP2CmdChar) return;
  
  uint8_t data[20] = {cmd, payloadLen};
  if (payloadLen > 0 && payloadLen < 18) {
    memcpy(data + 2, payload, payloadLen);
  }
  
  pP2CmdChar->writeValue(data, 2 + payloadLen);
  
  char hexStr[64] = "";
  for (int i = 0; i < 2 + payloadLen; i++) {
    char temp[8];
    sprintf(temp, "%02X ", data[i]);
    strcat(hexStr, temp);
  }
  char msg[128];
  sprintf(msg, "CMD sent: [%s]", hexStr);
  logEvent("P2", "TX", msg);
}

// Autenticar con P2
void authenticateP2() {
  logEvent("P2", "AUTH", "🔐 Sending PIN authentication (PLAINTEXT!)...");
  
  uint8_t authData[6];
  authData[0] = 0x00; // User ID high byte
  authData[1] = 0x01; // User ID low byte (User = 1)
  
  // PIN "123456" → bytes 0x12, 0x34, 0x56, 0x00 (BCD-like)
  authData[2] = 0x12;
  authData[3] = 0x34;
  authData[4] = 0x56;
  authData[5] = 0x00; // Padding
  
  char pinMsg[128];
  sprintf(pinMsg, "⚠️  Transmitting PIN in CLEAR: User=1, PIN=%s", P2_PIN);
  logEvent("P2", "VULN", pinMsg);
  
  sendCommandP2(0x01, authData, 6); // CMD_AUTH_PIN
}

// Conectar a P1
void connectToP1() {
  if (!p1Device) return;
  
  logEvent("P1", "BLE", "Attempting connection...");
  
  pClientP1 = BLEDevice::createClient();
  pClientP1->connect(p1Device);
  
  logEvent("P1", "BLE", "Connected!");
  
  BLERemoteService* pService = pClientP1->getService(P1_SERVICE_UUID);
  if (!pService) {
    logEvent("P1", "ERROR", "Service not found");
    pClientP1->disconnect();
    return;
  }
  
  pP1CmdChar = pService->getCharacteristic(P1_CMD_UUID);
  BLERemoteCharacteristic* pStateChar = pService->getCharacteristic(P1_STATE_UUID);
  
  if (!pP1CmdChar || !pStateChar) {
    logEvent("P1", "ERROR", "Characteristics not found");
    pClientP1->disconnect();
    return;
  }
  
  pStateChar->registerForNotify(p1NotifyCallback);
  logEvent("P1", "GATT", "Notifications enabled");
  
  p1Connected = true;
  logEvent("P1", "SYSTEM", "== READY ==");
}

// Conectar a P2
void connectToP2() {
  if (!p2Device) return;
  
  logEvent("P2", "BLE", "Attempting connection...");
  
  pClientP2 = BLEDevice::createClient();
  pClientP2->connect(p2Device);
  
  logEvent("P2", "BLE", "Connected!");
  
  BLERemoteService* pService = pClientP2->getService(P2_SERVICE_UUID);
  if (!pService) {
    logEvent("P2", "ERROR", "Service not found");
    pClientP2->disconnect();
    return;
  }
  
  pP2CmdChar = pService->getCharacteristic(P2_CMD_UUID);
  BLERemoteCharacteristic* pStateChar = pService->getCharacteristic(P2_STATE_UUID);
  
  if (!pP2CmdChar || !pStateChar) {
    logEvent("P2", "ERROR", "Characteristics not found");
    pClientP2->disconnect();
    return;
  }
  
  pStateChar->registerForNotify(p2NotifyCallback);
  logEvent("P2", "GATT", "Notifications enabled");
  
  p2Connected = true;
  logEvent("P2", "SYSTEM", "== READY - Authenticating... ==");
  
  delay(500);
  authenticateP2(); // Enviar PIN inmediatamente
}

// Escaneo de dispositivos
class AdvertisedDeviceCallbacks : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) {
    String name = advertisedDevice.getName().c_str();
    
    if (name == "ESP32_P1" && !p1Connected && !p1Device) {
      logEvent("SCAN", "FOUND", "ESP32_P1 detected!");
      p1Device = new BLEAdvertisedDevice(advertisedDevice);
      BLEDevice::getScan()->stop();
    }
    
    if (name == "ESP32_P2" && !p2Connected && !p2Device) {
      logEvent("SCAN", "FOUND", "ESP32_P2 detected!");
      p2Device = new BLEAdvertisedDevice(advertisedDevice);
      BLEDevice::getScan()->stop();
    }
  }
};

void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println("\n\n========================================");
  Serial.println("ESP32 BLE Central - Master Controller");
  Serial.println("Targets: ESP32_P1 (no auth) + ESP32_P2 (PIN)");
  Serial.println("========================================\n");
  
  logEvent("SYSTEM", "INIT", "Initializing BLE...");
  BLEDevice::init("ESP32_Master");
  
  BLEScan* pScan = BLEDevice::getScan();
  pScan->setAdvertisedDeviceCallbacks(new AdvertisedDeviceCallbacks());
  pScan->setActiveScan(true);
  pScan->setInterval(100);
  pScan->setWindow(99);
  
  logEvent("SYSTEM", "INIT", "Scanning for devices...");
}

void loop() {
  // Conectar a dispositivos encontrados
  if (p1Device && !p1Connected) {
    connectToP1();
  }
  
  if (p2Device && !p2Connected) {
    connectToP2();
  }
  
  // Escanear si falta algún dispositivo
  if ((!p1Device && !p1Connected) || (!p2Device && !p2Connected)) {
    BLEDevice::getScan()->start(5, false);
    delay(5000);
  }
  
  // Si no hay conexiones activas, esperar
  if (!p1Connected && !p2Connected) {
    delay(1000);
    return;
  }
  
  unsigned long currentTime = millis();
  
  // Comandos para P1 (cada 3 segundos) - SOLO SI ESTÁ CONECTADO
  if (p1Connected && (currentTime - lastP1Command > 3000)) {
    lastP1Command = currentTime;
    
    static uint8_t p1CommandSeq = 0;
    switch (p1CommandSeq++ % 4) {
      case 0: sendCommandP1(0x01, 0x01); break; // ECO mode
      case 1: sendCommandP1(0x03, 80); break;   // Brightness 80
      case 2: sendCommandP1(0x02); break;        // Get status
      case 3: sendCommandP1(0x05); break;        // Get telemetry
    }
  }
  
  // Comandos para P2 (cada 4 segundos) - SOLO SI ESTÁ CONECTADO
  if (p2Connected && (currentTime - lastP2Command > 4000)) {
    lastP2Command = currentTime;
    
    static uint8_t p2CommandSeq = 0;
    uint8_t payload[10];
    
    switch (p2CommandSeq++ % 6) {
      case 0: // Session start
        payload[0] = (currentTime >> 24) & 0xFF;
        payload[1] = (currentTime >> 16) & 0xFF;
        payload[2] = (currentTime >> 8) & 0xFF;
        payload[3] = currentTime & 0xFF;
        payload[4] = 0x01; // Tipo infantil
        sendCommandP2(0x02, payload, 5);
        break;
        
      case 1: // Set mode TURBO
        payload[0] = 0x02;
        sendCommandP2(0x10, payload, 1);
        break;
        
      case 2: // Set intensity 75%
        payload[0] = 75;
        sendCommandP2(0x11, payload, 1);
        break;
        
      case 3: // Set timer 45 min
        payload[0] = 0x00;
        payload[1] = 0x2D;
        sendCommandP2(0x12, payload, 2);
        break;
        
      case 4: // Event: Game complete, score 1500
        payload[0] = 0x01; // Game complete
        payload[1] = 0x05; // Score high byte
        payload[2] = 0xDC; // Score low byte (1500)
        sendCommandP2(0x20, payload, 3);
        break;
        
      case 5: // Reward: Level 5, 3 badges
        payload[0] = 0x05;
        payload[1] = 0x03;
        sendCommandP2(0x21, payload, 2);
        break;
    }
  }
  
  delay(100);
}
