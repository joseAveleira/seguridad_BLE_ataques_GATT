/*
 * ESP32 BLE Peripheral - IoT Sensor (P1)
 * 
 * Este código implementa un dispositivo periférico BLE que:
 * - Se anuncia como "ESP32_P1" (sensor IoT)
 * - Expone un servicio GATT "IoT genérico"
 * - Recibe comandos del central y responde con notificaciones de estado
 * - Simula un sensor IoT con modos, telemetría y control
 * 
 * Características GATT:
 * - cmd (UUID: 0x2A57): Write - Recibe comandos del central
 * - state (UUID: 0x2A58): Notify - Envía estado al central
 */

#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
#include <BLE2902.h>

// ==================== CONFIGURACIÓN ====================
// UUIDs del servicio y características (deben coincidir con el central)
#define SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define CMD_CHAR_UUID       "beb5483e-36e1-4688-b7f5-ea07361b26a8"
#define STATE_CHAR_UUID     "beb5483f-36e1-4688-b7f5-ea07361b26a8"

// Configuración del dispositivo
#define DEVICE_NAME "ESP32_P1"
#define LED_PIN 2  // LED integrado para indicación visual

// ==================== VARIABLES GLOBALES ====================
BLEServer* pServer = nullptr;
BLECharacteristic* pCmdCharacteristic = nullptr;
BLECharacteristic* pStateCharacteristic = nullptr;
bool deviceConnected = false;
bool oldDeviceConnected = false;

// Estado del dispositivo IoT simulado
struct DeviceState {
  uint8_t mode;           // 0=Normal, 1=Eco, 2=Turbo
  uint8_t brightness;     // 0-255
  uint16_t timer;         // Segundos
  uint32_t uptime;        // Tiempo encendido
  uint16_t cmdCounter;    // Contador de comandos recibidos
  int16_t temperature;    // Temperatura simulada (°C * 10)
  uint16_t humidity;      // Humedad simulada (% * 10)
  bool ledState;          // Estado del LED
} deviceState = {0, 100, 0, 0, 0, 250, 650, false};

unsigned long lastTelemetryUpdate = 0;
const unsigned long TELEMETRY_INTERVAL = 5000; // Actualizar telemetría cada 5s

// ==================== LOGGING ====================
void logEvent(const char* category, const char* message) {
  unsigned long timestamp = millis();
  Serial.printf("[%08lu] [PERIPH-%s] %s\n", timestamp, category, message);
}

void logCommand(const char* action, uint8_t* data, size_t length) {
  char hexStr[64] = "";
  char temp[8];
  for (size_t i = 0; i < length; i++) {
    sprintf(temp, "%02X ", data[i]);
    strcat(hexStr, temp);
  }
  
  char logMsg[128];
  sprintf(logMsg, "%s: [%s]", action, hexStr);
  logEvent("CMD", logMsg);
}

// ==================== CALLBACKS ====================
// Callback para conexión/desconexión del servidor
class ServerCallbacks : public BLEServerCallbacks {
  void onConnect(BLEServer* pServer) {
    deviceConnected = true;
    logEvent("BLE", "Central connected");
    digitalWrite(LED_PIN, HIGH);
  }

  void onDisconnect(BLEServer* pServer) {
    deviceConnected = false;
    logEvent("BLE", "Central disconnected");
    digitalWrite(LED_PIN, LOW);
  }
};

// ==================== PROCESAMIENTO DE COMANDOS ====================
void sendStateNotification(uint8_t stateType, uint8_t value1, uint8_t value2 = 0, uint8_t value3 = 0) {
  if (!deviceConnected) return;
  
  uint8_t stateData[4] = {stateType, value1, value2, value3};
  pStateCharacteristic->setValue(stateData, 4);
  pStateCharacteristic->notify();
  
  char logMsg[64];
  sprintf(logMsg, "STATE sent: [%02X %02X %02X %02X]", stateData[0], stateData[1], stateData[2], stateData[3]);
  logEvent("TX", logMsg);
}

void processCommand(uint8_t* data, size_t length) {
  if (length < 2) {
    logEvent("ERROR", "Command too short");
    return;
  }
  
  deviceState.cmdCounter++;
  logCommand("Received", data, length);
  
  uint8_t cmdType = data[0];
  uint8_t cmdParam = data[1];
  
  switch (cmdType) {
    case 0x01: // SET_MODE
      if (cmdParam <= 2) {
        deviceState.mode = cmdParam;
        const char* modes[] = {"NORMAL", "ECO", "TURBO"};
        char msg[64];
        sprintf(msg, "Mode changed to %s", modes[cmdParam]);
        logEvent("STATE", msg);
        
        // Responder con confirmación
        sendStateNotification(0x01, deviceState.mode, 0x00, 0x00);
      }
      break;
      
    case 0x02: // GET_STATUS
      logEvent("STATE", "Status requested");
      // Enviar estado actual: [tipo, modo, brightness, flags]
      sendStateNotification(0x02, deviceState.mode, deviceState.brightness, deviceState.ledState ? 0x01 : 0x00);
      break;
      
    case 0x03: // SET_BRIGHTNESS
      deviceState.brightness = cmdParam;
      char brightMsg[64];
      sprintf(brightMsg, "Brightness set to %d", deviceState.brightness);
      logEvent("STATE", brightMsg);
      
      // Confirmar nuevo brillo
      sendStateNotification(0x03, deviceState.brightness, 0x00, 0x00);
      break;
      
    case 0x04: // RESET_COUNTERS
      deviceState.cmdCounter = 0;
      deviceState.uptime = 0;
      logEvent("STATE", "Counters reset");
      sendStateNotification(0x04, 0x00, 0x00, 0x00);
      break;
      
    case 0x05: // GET_TELEMETRY
      logEvent("STATE", "Telemetry requested");
      // Enviar temperatura (2 bytes)
      sendStateNotification(0x05, 0x01, (deviceState.temperature >> 8) & 0xFF, deviceState.temperature & 0xFF);
      delay(50);
      // Enviar humedad (2 bytes)
      sendStateNotification(0x05, 0x02, (deviceState.humidity >> 8) & 0xFF, deviceState.humidity & 0xFF);
      break;
      
    case 0x06: // SET_TIMER
      deviceState.timer = cmdParam;
      char timerMsg[64];
      sprintf(timerMsg, "Timer set to %d seconds", deviceState.timer);
      logEvent("STATE", timerMsg);
      sendStateNotification(0x06, deviceState.timer, 0x00, 0x00);
      break;
      
    default:
      logEvent("ERROR", "Unknown command");
      // Enviar error
      sendStateNotification(0xFF, cmdType, 0xE0, 0x01); // Error: comando desconocido
      break;
  }
  
  // Log del contador de comandos
  char counterMsg[64];
  sprintf(counterMsg, "Commands processed: %d", deviceState.cmdCounter);
  logEvent("INFO", counterMsg);
}

// Callback para escritura en característica CMD
class CmdCharacteristicCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic* pCharacteristic) {
    std::string value = pCharacteristic->getValue();
    
    if (value.length() > 0) {
      uint8_t* data = (uint8_t*)value.data();
      processCommand(data, value.length());
    }
  }
};

// ==================== SIMULACIÓN DE TELEMETRÍA ====================
void updateTelemetry() {
  unsigned long currentTime = millis();
  
  if (currentTime - lastTelemetryUpdate >= TELEMETRY_INTERVAL) {
    lastTelemetryUpdate = currentTime;
    
    // Simular cambios en telemetría basados en el modo
    switch (deviceState.mode) {
      case 0: // Normal
        deviceState.temperature = 250 + random(-20, 20); // 25°C ±2°C
        deviceState.humidity = 650 + random(-50, 50);     // 65% ±5%
        break;
      case 1: // Eco
        deviceState.temperature = 220 + random(-15, 15); // 22°C ±1.5°C
        deviceState.humidity = 700 + random(-30, 30);     // 70% ±3%
        break;
      case 2: // Turbo
        deviceState.temperature = 350 + random(-30, 30); // 35°C ±3°C
        deviceState.humidity = 550 + random(-60, 60);     // 55% ±6%
        break;
    }
    
    deviceState.uptime = millis() / 1000;
    
    // Toggle LED state periodically
    deviceState.ledState = !deviceState.ledState;
    
    char telemetryMsg[128];
    sprintf(telemetryMsg, "Telemetry update - Temp: %.1f°C, Humidity: %.1f%%, Uptime: %lus", 
            deviceState.temperature / 10.0, 
            deviceState.humidity / 10.0,
            deviceState.uptime);
    logEvent("TELEM", telemetryMsg);
  }
}

// ==================== SETUP ====================
void setup() {
  Serial.begin(115200);
  delay(1000);
  
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  
  Serial.println("\n\n========================================");
  Serial.println("ESP32 BLE Peripheral - IoT Sensor");
  Serial.println("Device: " DEVICE_NAME);
  Serial.println("========================================\n");
  
  logEvent("SYSTEM", "Initializing BLE...");
  
  // Inicializar BLE
  BLEDevice::init(DEVICE_NAME);
  
  // Crear servidor BLE
  pServer = BLEDevice::createServer();
  pServer->setCallbacks(new ServerCallbacks());
  logEvent("BLE", "BLE Server created");
  
  // Crear servicio
  BLEService* pService = pServer->createService(SERVICE_UUID);
  logEvent("GATT", "Service created");
  
  // Crear característica CMD (Write)
  pCmdCharacteristic = pService->createCharacteristic(
    CMD_CHAR_UUID,
    BLECharacteristic::PROPERTY_WRITE
  );
  pCmdCharacteristic->setCallbacks(new CmdCharacteristicCallbacks());
  logEvent("GATT", "CMD characteristic created (Write)");
  
  // Crear característica STATE (Notify)
  pStateCharacteristic = pService->createCharacteristic(
    STATE_CHAR_UUID,
    BLECharacteristic::PROPERTY_NOTIFY
  );
  pStateCharacteristic->addDescriptor(new BLE2902());
  logEvent("GATT", "STATE characteristic created (Notify)");
  
  // Iniciar servicio
  pService->start();
  logEvent("GATT", "Service started");
  
  // Iniciar advertising
  BLEAdvertising* pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->addServiceUUID(SERVICE_UUID);
  pAdvertising->setScanResponse(true);
  pAdvertising->setMinPreferred(0x06);
  pAdvertising->setMinPreferred(0x12);
  BLEDevice::startAdvertising();
  
  logEvent("BLE", "Advertising started");
  logEvent("SYSTEM", "== PERIPHERAL READY - Waiting for central ==");
  
  Serial.println("\nDevice info:");
  Serial.printf("  Name: %s\n", DEVICE_NAME);
  Serial.printf("  Service UUID: %s\n", SERVICE_UUID);
  Serial.printf("  CMD UUID: %s\n", CMD_CHAR_UUID);
  Serial.printf("  STATE UUID: %s\n\n", STATE_CHAR_UUID);
}

// ==================== LOOP ====================
void loop() {
  // Gestionar reconexión si es necesario
  if (!deviceConnected && oldDeviceConnected) {
    delay(500);
    logEvent("BLE", "Restarting advertising...");
    pServer->startAdvertising();
    oldDeviceConnected = deviceConnected;
  }
  
  // Conectado por primera vez
  if (deviceConnected && !oldDeviceConnected) {
    oldDeviceConnected = deviceConnected;
  }
  
  // Actualizar telemetría simulada
  updateTelemetry();
  
  delay(100);
}
