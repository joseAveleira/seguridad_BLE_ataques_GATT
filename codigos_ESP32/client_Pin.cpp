/*
 * ESP32 BLE Peripheral - IoT Device with PIN (P2)
 * 
 * Dispositivo que simula un juguete/wearable con:
 * - Autenticación por PIN (4 dígitos en TEXTO CLARO)
 * - Control parental (modos, timers, perfiles)
 * - Sistema de eventos y recompensas
 * 
 * VULNERABILIDAD DEMOSTRADA:
 * El PIN viaja sin cifrar → Atacante puede capturarlo y reutilizarlo
 */

#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
#include <BLE2902.h>

// ==================== CONFIGURACIÓN ====================
#define SERVICE_UUID        "5fafc301-2fb5-459e-8fcc-c5c9c331915c"
#define CMD_CHAR_UUID       "ceb5483e-46e1-4688-b7f5-ea07361b27a9"
#define STATE_CHAR_UUID     "ceb5483f-46e1-4688-b7f5-ea07361b27a9"

#define DEVICE_NAME "ESP32_P2"
#define LED_PIN 2
#define CORRECT_PIN "123456"  // PIN en texto claro (4-6 dígitos)

// ==================== VARIABLES GLOBALES ====================
BLEServer* pServer = nullptr;
BLECharacteristic* pCmdCharacteristic = nullptr;
BLECharacteristic* pStateCharacteristic = nullptr;
bool deviceConnected = false;
bool oldDeviceConnected = false;

// Estado del dispositivo con autenticación
struct SecureDeviceState {
  bool authenticated;      // ¿Sesión autenticada?
  uint16_t userId;        // ID de usuario actual
  uint32_t sessionStart;  // Timestamp de inicio sesión
  uint8_t sessionType;    // 0=normal, 1=infantil
  uint8_t keepaliveCount; // Contador de latidos
  
  // Configuración
  uint8_t mode;           // 0=Eco, 1=Normal, 2=Turbo, 3=Noche
  uint8_t intensity;      // 0-100 (brightness/volumen)
  uint16_t timerMinutes;  // Límite de uso en minutos
  uint8_t ageProfile;     // 0=3-5, 1=6-8, 2=9-12 años
  uint8_t preferences;    // Flags: bit0=sonido, bit1=luz, bit2=vibración
  
  // Estadísticas
  uint16_t cmdCounter;
  uint8_t currentLevel;   // Nivel de progreso (0-10)
  uint8_t badges;         // Logros desbloqueados
  
  // Telemetría simulada
  int16_t temperature;    // Temperatura °C * 10
  uint8_t heartRate;      // Frecuencia cardíaca
  uint16_t steps;         // Pasos del día
  uint8_t battery;        // Batería %
  int16_t latitude;       // Latitud * 100
  int16_t longitude;      // Longitud * 100
} deviceState = {false, 0, 0, 0, 0, 0, 50, 30, 0, 0x07, 0, 0, 0, 365, 75, 1250, 85, 4047, -374};

// ==================== LOGGING ====================
void logEvent(const char* category, const char* message) {
  unsigned long timestamp = millis();
  Serial.printf("[%08lu] [P2-%s] %s\n", timestamp, category, message);
}

void logCommand(const char* action, uint8_t* data, size_t length) {
  char hexStr[128] = "";
  char temp[8];
  for (size_t i = 0; i < length && i < 32; i++) {
    sprintf(temp, "%02X ", data[i]);
    strcat(hexStr, temp);
  }
  char logMsg[256];
  sprintf(logMsg, "%s: [%s]", action, hexStr);
  logEvent("CMD", logMsg);
}

// ==================== NOTIFICACIONES ====================
void sendStateNotification(uint8_t stateType, uint8_t* payload, size_t payloadLen) {
  if (!deviceConnected) return;
  
  uint8_t stateData[20] = {stateType};
  size_t totalLen = 1 + payloadLen;
  if (totalLen > 20) totalLen = 20;
  
  memcpy(stateData + 1, payload, payloadLen);
  pStateCharacteristic->setValue(stateData, totalLen);
  pStateCharacteristic->notify();
  
  char logMsg[128];
  sprintf(logMsg, "STATE sent: Type=0x%02X, Len=%d", stateType, payloadLen);
  logEvent("TX", logMsg);
}

// ==================== PROCESAMIENTO DE COMANDOS ====================
void processCommand(uint8_t* data, size_t length) {
  if (length < 2) {
    logEvent("ERROR", "Command too short");
    return;
  }
  
  deviceState.cmdCounter++;
  logCommand("Received", data, length);
  
  uint8_t cmdType = data[0];
  uint8_t cmdLen = data[1];
  uint8_t* cmdData = (cmdLen > 0 && length >= 2 + cmdLen) ? &data[2] : nullptr;
  
  // Comandos que NO requieren autenticación
  if (cmdType == 0x01) { // CMD_AUTH_PIN
    if (cmdLen < 6) {
      logEvent("AUTH", "❌ PIN packet too short");
      uint8_t response[] = {0x00}; // Auth failed
      sendStateNotification(0x01, response, 1);
      return;
    }
    
    uint16_t userId = (cmdData[0] << 8) | cmdData[1];
    char receivedPin[7] = "";
    sprintf(receivedPin, "%02X%02X%02X%02X", cmdData[2], cmdData[3], cmdData[4], cmdData[5]);
    
    char logMsg[128];
    sprintf(logMsg, "🔐 Auth attempt - User: %d, PIN: %s (PLAINTEXT!)", userId, receivedPin);
    logEvent("AUTH", logMsg);
    
    // Verificar PIN (en producción sería hash, aquí texto claro)
    if (strcmp(receivedPin, CORRECT_PIN) == 0) {
      deviceState.authenticated = true;
      deviceState.userId = userId;
      deviceState.sessionStart = millis();
      
      sprintf(logMsg, "✅ Authentication SUCCESS - User %d logged in", userId);
      logEvent("AUTH", logMsg);
      
      uint8_t response[] = {0x01, (uint8_t)(userId >> 8), (uint8_t)(userId & 0xFF)};
      sendStateNotification(0x01, response, 3);
      digitalWrite(LED_PIN, HIGH);
    } else {
      logEvent("AUTH", "❌ Authentication FAILED - Wrong PIN");
      uint8_t response[] = {0x00};
      sendStateNotification(0x01, response, 1);
    }
    return;
  }
  
  // Comandos que SÍ requieren autenticación
  if (!deviceState.authenticated) {
    logEvent("SEC", "⚠️  Command rejected - Not authenticated");
    uint8_t response[] = {0xE1}; // Error: no autenticado
    sendStateNotification(0xFF, response, 1);
    return;
  }
  
  switch (cmdType) {
    case 0x02: { // CMD_SESSION_START
      if (cmdLen < 5) break;
      uint32_t timestamp = (cmdData[0] << 24) | (cmdData[1] << 16) | (cmdData[2] << 8) | cmdData[3];
      deviceState.sessionType = cmdData[4];
      
      char msg[64];
      sprintf(msg, "Session started - Type: %d, TS: %lu", deviceState.sessionType, timestamp);
      logEvent("SESSION", msg);
      
      uint8_t response[] = {0x01, deviceState.sessionType};
      sendStateNotification(0x02, response, 2);
      break;
    }
    
    case 0x03: { // CMD_KEEPALIVE
      deviceState.keepaliveCount = cmdData[0];
      char msg[32];
      sprintf(msg, "Keepalive #%d", deviceState.keepaliveCount);
      logEvent("SESSION", msg);
      
      uint8_t response[] = {deviceState.keepaliveCount};
      sendStateNotification(0x03, response, 1);
      break;
    }
    
    case 0x10: { // CMD_SET_MODE
      deviceState.mode = cmdData[0];
      const char* modes[] = {"ECO", "NORMAL", "TURBO", "NOCHE"};
      char msg[64];
      sprintf(msg, "Mode changed to %s", modes[deviceState.mode % 4]);
      logEvent("CONFIG", msg);
      
      uint8_t response[] = {deviceState.mode};
      sendStateNotification(0x10, response, 1);
      break;
    }
    
    case 0x11: { // CMD_SET_INTENSITY
      deviceState.intensity = cmdData[0];
      char msg[64];
      sprintf(msg, "Intensity set to %d%%", deviceState.intensity);
      logEvent("CONFIG", msg);
      
      uint8_t response[] = {deviceState.intensity};
      sendStateNotification(0x11, response, 1);
      break;
    }
    
    case 0x12: { // CMD_SET_TIMER
      deviceState.timerMinutes = (cmdData[0] << 8) | cmdData[1];
      char msg[64];
      sprintf(msg, "Timer set to %d minutes", deviceState.timerMinutes);
      logEvent("CONFIG", msg);
      
      uint8_t response[] = {(uint8_t)(deviceState.timerMinutes >> 8), (uint8_t)(deviceState.timerMinutes & 0xFF)};
      sendStateNotification(0x12, response, 2);
      break;
    }
    
    case 0x13: { // CMD_SET_PROFILE
      deviceState.ageProfile = cmdData[0];
      deviceState.preferences = cmdData[1];
      const char* profiles[] = {"3-5 años", "6-8 años", "9-12 años"};
      char msg[64];
      sprintf(msg, "Profile: %s, Prefs: 0x%02X", profiles[deviceState.ageProfile % 3], deviceState.preferences);
      logEvent("CONFIG", msg);
      
      uint8_t response[] = {deviceState.ageProfile, deviceState.preferences};
      sendStateNotification(0x13, response, 2);
      break;
    }
    
    case 0x20: { // CMD_EVENT
      uint8_t eventType = cmdData[0];
      uint16_t eventValue = (cmdData[1] << 8) | cmdData[2];
      const char* events[] = {"Button", "Game Complete", "Error"};
      char msg[64];
      sprintf(msg, "Event: %s, Value: %d", events[eventType % 3], eventValue);
      logEvent("EVENT", msg);
      
      uint8_t response[] = {eventType, (uint8_t)(eventValue >> 8), (uint8_t)(eventValue & 0xFF)};
      sendStateNotification(0x20, response, 3);
      break;
    }
    
    case 0x21: { // CMD_REWARD
      deviceState.currentLevel = cmdData[0];
      deviceState.badges = cmdData[1];
      char msg[64];
      sprintf(msg, "🎮 Reward - Level: %d, Badges: %d", deviceState.currentLevel, deviceState.badges);
      logEvent("EVENT", msg);
      
      uint8_t response[] = {deviceState.currentLevel, deviceState.badges};
      sendStateNotification(0x21, response, 2);
      break;
    }
    
    case 0x99: { // CMD_LOGOUT (cerrar sesión)
      logEvent("AUTH", "🔓 User logged out");
      deviceState.authenticated = false;
      deviceState.userId = 0;
      digitalWrite(LED_PIN, LOW);
      
      uint8_t response[] = {0x00};
      sendStateNotification(0x99, response, 1);
      break;
    }
    
    default:
      logEvent("ERROR", "Unknown command");
      uint8_t response[] = {cmdType, 0xE0};
      sendStateNotification(0xFF, response, 2);
      break;
  }
  
  char counterMsg[64];
  sprintf(counterMsg, "Commands processed: %d (Auth: %s)", 
          deviceState.cmdCounter, 
          deviceState.authenticated ? "YES" : "NO");
  logEvent("INFO", counterMsg);
}

// Callback para escritura en CMD
class CmdCharacteristicCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic* pCharacteristic) {
    std::string value = pCharacteristic->getValue();
    if (value.length() > 0) {
      uint8_t* data = (uint8_t*)value.data();
      processCommand(data, value.length());
    }
  }
};

// Callback de conexión
class ServerCallbacks : public BLEServerCallbacks {
  void onConnect(BLEServer* pServer) {
    deviceConnected = true;
    logEvent("BLE", "Central connected");
    // NO encender LED hasta autenticación exitosa
  }

  void onDisconnect(BLEServer* pServer) {
    deviceConnected = false;
    deviceState.authenticated = false; // Limpiar sesión
    logEvent("BLE", "Central disconnected - Session cleared");
    digitalWrite(LED_PIN, LOW);
  }
};

// ==================== SETUP ====================
void setup() {
  Serial.begin(115200);
  delay(1000);
  
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  
  Serial.println("\n\n========================================");
  Serial.println("ESP32 BLE Peripheral - Secure Device (P2)");
  Serial.println("Device: " DEVICE_NAME);
  Serial.println("⚠️  PIN-based auth (PLAINTEXT - VULNERABLE)");
  Serial.println("========================================\n");
  
  logEvent("SYSTEM", "Initializing BLE...");
  
  BLEDevice::init(DEVICE_NAME);
  
  pServer = BLEDevice::createServer();
  pServer->setCallbacks(new ServerCallbacks());
  logEvent("BLE", "BLE Server created");
  
  BLEService* pService = pServer->createService(SERVICE_UUID);
  logEvent("GATT", "Service created");
  
  pCmdCharacteristic = pService->createCharacteristic(
    CMD_CHAR_UUID,
    BLECharacteristic::PROPERTY_WRITE
  );
  pCmdCharacteristic->setCallbacks(new CmdCharacteristicCallbacks());
  logEvent("GATT", "CMD characteristic created (Write)");
  
  pStateCharacteristic = pService->createCharacteristic(
    STATE_CHAR_UUID,
    BLECharacteristic::PROPERTY_NOTIFY
  );
  pStateCharacteristic->addDescriptor(new BLE2902());
  logEvent("GATT", "STATE characteristic created (Notify)");
  
  pService->start();
  logEvent("GATT", "Service started");
  
  BLEAdvertising* pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->addServiceUUID(SERVICE_UUID);
  pAdvertising->setScanResponse(true);
  pAdvertising->setMinPreferred(0x06);
  pAdvertising->setMinPreferred(0x12);
  BLEDevice::startAdvertising();
  
  logEvent("BLE", "Advertising started");
  logEvent("SYSTEM", "== PERIPHERAL READY - Awaiting authentication ==");
  
  Serial.println("\nDevice info:");
  Serial.printf("  Name: %s\n", DEVICE_NAME);
  Serial.printf("  Correct PIN: %s (VISIBLE IN CODE!)\n", CORRECT_PIN);
  Serial.printf("  Service UUID: %s\n\n", SERVICE_UUID);
}

// ==================== LOOP ====================
void loop() {
  if (!deviceConnected && oldDeviceConnected) {
    delay(500);
    logEvent("BLE", "Restarting advertising...");
    pServer->startAdvertising();
    oldDeviceConnected = deviceConnected;
  }
  
  if (deviceConnected && !oldDeviceConnected) {
    oldDeviceConnected = deviceConnected;
  }
  
  // Enviar telemetría automática cada 10 segundos SI está autenticado
  static unsigned long lastTelemetry = 0;
  unsigned long currentTime = millis();
  
  if (deviceConnected && deviceState.authenticated && (currentTime - lastTelemetry > 10000)) {
    lastTelemetry = currentTime;
    
    // Simular cambios en telemetría
    deviceState.temperature = 360 + random(-20, 30); // 36°C ±2°C
    deviceState.heartRate = 75 + random(-10, 15);    // 75 bpm ±10
    deviceState.steps += random(50, 200);            // Incremento de pasos
    deviceState.battery = max(0, deviceState.battery - random(0, 2)); // Batería baja lentamente
    deviceState.latitude += random(-5, 5);           // Pequeño movimiento GPS
    deviceState.longitude += random(-5, 5);
    
    // Enviar telemetría en múltiples notificaciones
    uint8_t telemetryData[10];
    
    // Paquete 1: Temperatura y frecuencia cardíaca
    telemetryData[0] = 0x01; // Tipo: vitales
    telemetryData[1] = (deviceState.temperature >> 8) & 0xFF;
    telemetryData[2] = deviceState.temperature & 0xFF;
    telemetryData[3] = deviceState.heartRate;
    sendStateNotification(0xA0, telemetryData, 4); // 0xA0 = TELEMETRY
    delay(50);
    
    // Paquete 2: Actividad
    telemetryData[0] = 0x02; // Tipo: actividad
    telemetryData[1] = (deviceState.steps >> 8) & 0xFF;
    telemetryData[2] = deviceState.steps & 0xFF;
    telemetryData[3] = deviceState.battery;
    sendStateNotification(0xA0, telemetryData, 4);
    delay(50);
    
    // Paquete 3: Ubicación
    telemetryData[0] = 0x03; // Tipo: GPS
    telemetryData[1] = (deviceState.latitude >> 8) & 0xFF;
    telemetryData[2] = deviceState.latitude & 0xFF;
    telemetryData[3] = (deviceState.longitude >> 8) & 0xFF;
    telemetryData[4] = deviceState.longitude & 0xFF;
    sendStateNotification(0xA0, telemetryData, 5);
    
    char telemetryLog[256];
    sprintf(telemetryLog, "📡 Telemetry: Temp=%.1f°C, HR=%d bpm, Steps=%d, Battery=%d%%, GPS=(%.2f,%.2f)",
            deviceState.temperature / 10.0,
            deviceState.heartRate,
            deviceState.steps,
            deviceState.battery,
            deviceState.latitude / 100.0,
            deviceState.longitude / 100.0);
    logEvent("TELEM", telemetryLog);
  }
  
  delay(100);
}
