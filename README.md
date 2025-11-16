# Auditoría de Seguridad en Dispositivos IoT BLE: Técnicas de Sniffing Pasivo y Ataques GATT

**Artículo presentado en RECSI 2025**

Este repositorio contiene el código completo, datasets y metodología utilizada para la investigación sobre vulnerabilidades de seguridad en dispositivos IoT Bluetooth Low Energy (BLE), con énfasis en ataques a nivel de protocolo GATT y técnicas de sniffing pasivo.

## Tabla de Contenidos

- [Descripción General](#descripción-general)
- [Testbed Experimental](#testbed-experimental)
- [Herramientas de Análisis](#herramientas-de-análisis)
- [Dataset Generado](#dataset-generado)
- [Configuración del Entorno](#configuración-del-entorno)
- [Reproducibilidad](#reproducibilidad)
- [Resultados y Publicaciones](#resultados-y-publicaciones)
- [Referencias](#referencias)

---

## Descripción General

Esta investigación presenta un análisis exhaustivo de las vulnerabilidades de seguridad en dispositivos IoT que utilizan Bluetooth Low Energy (BLE), demostrando ataques prácticos a nivel de protocolo GATT (Generic Attribute Profile). El trabajo se centra en:

- **Sniffing pasivo**: Captura de tráfico BLE utilizando hardware especializado (nRF52840).
- **Ataques activos**: Explotación de vulnerabilidades en dispositivos sin autenticación y con autenticación débil.
- **Análisis forense**: Extracción y análisis de comandos GATT desde capturas PCAP.
- **Machine Learning**: Generación de dataset etiquetado para detección de anomalías.

### Vulnerabilidades Identificadas

| ID | Vulnerabilidad | Impacto | Dispositivo Afectado |
|----|----------------|---------|----------------------|
| VULN-01 | Ausencia de autenticación en conexión | Conexión directa sin credenciales | ESP32_P1 |
| VULN-02 | PIN en texto plano | Captura de credenciales por sniffing | ESP32_P2 |
| VULN-03 | Sin cifrado en capa de aplicación | Comandos visibles en claro | ESP32_P1, ESP32_P2 |
| VULN-04 | Sin timeout de sesión | Secuestro de conexión indefinido | Ambos |
| VULN-05 | Sin rate limiting | DoS por flooding de comandos | Ambos |
| VULN-06 | Falta de validación de payload | Buffer overflow potencial | Ambos |

---

## Testbed Experimental

El entorno controlado consiste en tres dispositivos ESP32 configurados para simular un escenario IoT realista con diferentes niveles de seguridad.

### Arquitectura del Testbed

```
┌─────────────────────────────────────────────────────────────┐
│                    ENTORNO CONTROLADO                       │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐ │
│  │  ESP32 #1    │    │  ESP32 #2    │    │  ESP32 #3    │ │
│  │  Peripheral  │    │  Peripheral  │    │   Central    │ │
│  ├──────────────┤    ├──────────────┤    ├──────────────┤ │
│  │ ESP32_P1     │    │ ESP32_P2     │    │   Master     │ │
│  │ Sin Auth     │    │ Con PIN      │    │   Legítimo   │ │
│  │ MAC: Fija    │    │ MAC: Random  │    │              │ │
│  └──────▲───────┘    └──────▲───────┘    └───────┬──────┘ │
│         │                    │                    │        │
│         └────────────────────┴────────────────────┘        │
│                   Conexiones BLE                           │
└─────────────────────────────────────────────────────────────┘
                          │
                          │ Captura Pasiva
                          ▼
              ┌───────────────────────┐
              │  nRF52840 Dongles     │
              │  (2x Sniffers BLE)    │
              └───────────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Wireshark + tshark   │
              │  Análisis Offline     │
              └───────────────────────┘
```

### Dispositivos ESP32

#### ESP32 #1 - Peripheral sin Autenticación (P1)

**Firmware**: `codigos_ESP32/client.cpp`

Simula un dispositivo IoT genérico (sensor, actuador) sin mecanismos de seguridad:

- **Nombre BLE**: ESP32_P1
- **MAC Address**: EC:E3:34:B2:E0:C2 (fija)
- **Servicio GATT**: 4fafc201-1fb5-459e-8fcc-c5c9c331914b
- **Características**:
  - Command (Write): beb5483e-36e1-4688-b7f5-ea07361b26a8
  - State (Notify): beb5483f-36e1-4688-b7f5-ea07361b26a8
- **Vulnerabilidades**: VULN-01, VULN-03, VULN-04, VULN-05, VULN-06

**Comandos soportados**:

| Comando | Byte | Parámetros | Función |
|---------|------|------------|---------|
| SET_MODE | 0x01 | 0x00 (Eco) / 0x01 (Turbo) | Cambiar modo operación |
| SET_LED | 0x02 | 0x00 (OFF) / 0x01 (ON) | Control de LED |
| SET_BRIGHTNESS | 0x03 | 0x00-0xFF | Ajustar brillo (0-255) |
| SET_TIMER | 0x04 | 0x00-0xFF | Temporizador en minutos |
| RESET | 0x05 | N/A | Reiniciar dispositivo |

#### ESP32 #2 - Peripheral con PIN (P2)

**Firmware**: `codigos_ESP32/client_Pin.cpp`

Simula un dispositivo con autenticación débil (PIN en texto plano):

- **Nombre BLE**: ESP32_P2
- **MAC Address**: Aleatorizada
- **Servicio GATT**: 5fafc301-2fb5-459e-8fcc-c5c9c331915c
- **PIN de autenticación**: "123456" (texto claro)
- **Vulnerabilidades**: VULN-02, VULN-03, VULN-04

**Comandos adicionales**:

| Comando | Byte | Función |
|---------|------|---------|
| AUTH_REQUEST | 0x10 | Autenticación con PIN (6 bytes ASCII) |
| SET_PROFILE | 0x20 | Configurar perfil de usuario |
| GET_TELEMETRY | 0x30 | Solicitar telemetría (temperatura, HR) |
| SET_PARENTAL_LOCK | 0x40 | Control parental |

#### ESP32 #3 - Central/Master Legítimo

**Firmware**: `codigos_ESP32/master.cpp`

Cliente BLE que controla los dos periféricos, simulando un controlador legítimo:

- **Función**: Conectar y enviar comandos a P1 y P2
- **Credenciales**: PIN hardcodeado en código fuente
- **Uso**: Establecer baseline de tráfico normal

### Hardware de Captura

#### nRF52840 Dongles (2x)

**Especificaciones**:
- Modelo: Nordic nRF52840 Dongle (PCA10059)
- Firmware: nRF Sniffer for Bluetooth LE v4.1.1
- Sensibilidad: -95 dBm @ 1 Mbps, -103 dBm @ Long Range
- Canales: 40 canales BLE con frequency hopping tracking
- Interfaz: USB 2.0 (CDC ACM para Wireshark)

**Configuración**:
- Sniffer #1 (COM12): Captura de tráfico normal
- Sniffer #2 (COM13): Captura durante ataques activos
- Modo: Follow con MAC tracking

---

## Herramientas de Análisis

### Scripts Python de Ataque

#### 1. Scanner y Reconocimiento (`ble_scanner.py`)

Escaneo y enumeración de dispositivos BLE:

```bash
# Escaneo general
python ble_scanner.py

# Escaneo de dispositivo específico
python ble_scanner.py --target ESP32_P1

# Exportar resultados
python ble_scanner.py --export scan_results.json
```

**Características**:
- Enumeración de servicios GATT
- Análisis de características (Read/Write/Notify)
- Detección de permisos
- Fingerprinting de dispositivos ESP32

#### 2. Ataque Directo a P1 (`ble_attack_p1.py`)

Explotación de ESP32_P1 sin autenticación:

```bash
# Conexión por nombre
python ble_attack_p1.py --target ESP32_P1

# Conexión por MAC
python ble_attack_p1.py --address EC:E3:34:B2:E0:C2

# Ataque DoS (brillo aleatorio)
python ble_attack_p1.py --target ESP32_P1 --attack dos-brightness

# Secuestro y modo turbo
python ble_attack_p1.py --target ESP32_P1 --attack hijack-turbo

# Suite completa
python ble_attack_p1.py --target ESP32_P1 --attack full
```

**Ataques implementados**:
- DoS por flooding de comandos
- Manipulación de configuración
- Secuestro de sesión
- Envío de comandos maliciosos

#### 3. Secuestro de Conexión (`ble_connection_hijack.py`)

DoS a nivel de protocolo mediante monopolización del canal BLE:

```bash
# Conexión persistente (5 minutos)
python ble_connection_hijack.py --address EC:E3:34:B2:E0:C2 --duration 300

# Con keep-alive activo
python ble_connection_hijack.py --address EC:E3:34:B2:E0:C2 --duration 600 --keep-alive

# Modo agresivo (reconexión automática)
python ble_connection_hijack.py --address EC:E3:34:B2:E0:C2 --duration inf --aggressive

# Con logging
python ble_connection_hijack.py --address EC:E3:34:B2:E0:C2 --duration 300 --log hijack_session.json
```

**Técnica**:
- Conexión BLE antes que el cliente legítimo
- Mantener sesión abierta indefinidamente
- Bloquear al usuario legítimo (single-central limitation)
- No requiere jamming RF (ataque de protocolo)

#### 4. Inyección de Payloads Maliciosos (`ble_payload_injection.py`)

Fuzzing y explotación de parsers GATT vulnerables:

```bash
# Buffer overflow
python ble_payload_injection.py --address EC:E3:34:B2:E0:C2 --mode overflow

# Inyección de caracteres especiales
python ble_payload_injection.py --address EC:E3:34:B2:E0:C2 --mode special-chars

# Format strings
python ble_payload_injection.py --address EC:E3:34:B2:E0:C2 --mode format-string

# Integer overflow
python ble_payload_injection.py --address EC:E3:34:B2:E0:C2 --mode integer-overflow

# Suite completa de fuzzing
python ble_payload_injection.py --address EC:E3:34:B2:E0:C2 --mode full --log injection.json

# Payload personalizado
python ble_payload_injection.py --address EC:E3:34:B2:E0:C2 --custom-payload "41414141414141414141"
```

**Vulnerabilidades exploradas**:
- Buffer overflows
- Format string attacks
- Command injection
- Integer overflows
- Null byte injection

### Scripts de Análisis Forense

#### 5. Análisis de Comandos PCAP (`analyze_pcap_commands.py`)

Extracción y análisis de comandos GATT desde capturas:

```bash
# Análisis básico
python analyze_pcap_commands.py capture.pcapng

# Con exportación JSON
python analyze_pcap_commands.py capture.pcapng --export resultados.json

# Modo verbose
python analyze_pcap_commands.py capture.pcapng --verbose
```

**Análisis realizado**:
- Extracción de Write Commands (opcode 0x52)
- Identificación de comandos propietarios
- Estadísticas de uso
- Detección de patrones anómalos
- Timeline de comandos

---

## Dataset Generado

El proyecto ha generado un dataset estructurado para investigación en detección de anomalías en tráfico BLE.

### Descripción del Dataset

**Archivo**: `dataset/bluetooth_gatt_dataset.csv`

- **Tamaño**: ~3.1 MB
- **Instancias**: 26,465 paquetes
- **Características**: 12 campos técnicos + 1 etiqueta
- **Balance**: 95.25% normal, 4.75% ataques
- **Formato**: CSV listo para análisis con pandas, scikit-learn, TensorFlow

### Características del Dataset

| Campo | Descripción | Tipo |
|-------|-------------|------|
| frame.number | Número secuencial de paquete | int |
| frame.time_epoch | Timestamp Unix | float |
| frame.len | Tamaño del frame en bytes | int |
| btle.length | Longitud del payload BLE | int |
| btle.central_bd_addr | MAC del dispositivo central | string |
| btle.peripheral_bd_addr | MAC del dispositivo periférico | string |
| btle.access_address | Access Address del enlace BLE | hex |
| btle.data_header.llid | Link Layer ID (tipo de PDU) | int |
| btatt.opcode | Opcode GATT (operación) | hex |
| btatt.handle | Handle GATT (característica) | hex |
| btatt.value | Valor leído/escrito | hex |
| inter_arrival_time | Tiempo entre paquetes (ms) | float |
| **type** | **Etiqueta: attack / normal** | **string** |

### Scripts de Dataset

#### Extracción (`dataset/extract_bluetooth_dataset.py`)

Procesa archivos PCAPNG y genera CSV etiquetado:

```bash
python dataset/extract_bluetooth_dataset.py capture.pcapng
```

**Funcionalidades**:
- Extracción con tshark
- Filtrado de tramas irrelevantes (56.8% eliminadas)
- Etiquetado automático usando timestamps de ataques
- Cálculo de inter-arrival time
- Generación de CSV estructurado

#### Análisis Estadístico (`dataset/analyze_dataset.py`)

Análisis exploratorio del dataset:

```bash
python dataset/analyze_dataset.py
```

**Análisis generado**:
- Distribución de clases (normal/attack)
- Opcodes más frecuentes por clase
- Análisis temporal (inter-arrival time)
- Dispositivos involucrados
- Estadísticas descriptivas

### Descubrimientos Clave

**Patrones de Ataque**:
- Predominancia de Write Request (0x12): 28.81% en ataques vs. 0% en normal
- Write Response (0x13): 27.12% en ataques
- Ataques más "lentos": IAT promedio de 24.5 ms vs. 12.7 ms en normal

**Tráfico Normal**:
- Mayor diversidad de opcodes
- Read By Type Request (0x08): 17.41%
- Write Command (0x52): 13.39%

**Dispositivos**:
- 2 dispositivos centrales (masters)
- 1 dispositivo periférico (slave - target)

### Uso para Machine Learning

El dataset es adecuado para:

**Detección Supervisada**:
- Random Forest, SVM, Neural Networks
- Clasificación binaria (normal/attack)
- Feature importance analysis

**Detección de Anomalías**:
- Isolation Forest
- One-Class SVM
- Autoencoders

**Análisis Temporal**:
- LSTM/GRU para secuencias
- Análisis de patrones temporales
- Detección de comportamiento anómalo

**Ejemplo de uso**:

```python
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Cargar dataset
df = pd.read_csv('dataset/bluetooth_gatt_dataset.csv')

# Preparar datos
X = df.drop(['type'], axis=1)
y = df['type'].map({'normal': 0, 'attack': 1})

# Entrenar modelo
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)
clf = RandomForestClassifier(n_estimators=100)
clf.fit(X_train, y_train)

# Evaluar
accuracy = clf.score(X_test, y_test)
print(f"Accuracy: {accuracy:.4f}")
```

---

## Configuración del Entorno

### Hardware Requerido

**Para reproducir ataques**:
- 3x ESP32 DevKit (Bluetooth 4.2 BLE + Classic)
- 2x nRF52840 Dongle (Nordic Semiconductor)
- PC con Bluetooth 5.0+ y 4 puertos USB 3.0

**Para solo análisis**:
- PC con Windows/Linux/macOS
- Archivos PCAP incluidos en el repositorio

### Software Requerido

#### Sistema Operativo Base

**Windows**:
- Windows 11 Pro 23H2 o superior
- Wireshark 4.2.0+
- Python 3.11+

**Linux** (alternativa):
- Ubuntu 22.04 LTS o superior
- Wireshark 4.x
- Python 3.10+

#### Herramientas de Captura

1. **Wireshark** (v4.2.0+)
   ```powershell
   # Windows: Descargar desde https://www.wireshark.org/
   # Linux:
   sudo apt install wireshark tshark
   sudo usermod -aG wireshark $USER
   ```

2. **nRF Sniffer for Bluetooth LE** (v4.1.1)
   ```
   Descargar desde: https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE
   Instalar plugin extcap en Wireshark
   ```

3. **nRF Connect for Desktop** (v4.3.0)
   ```
   Herramientas auxiliares para flashear firmware nRF
   ```

#### Bibliotecas Python

Crear entorno virtual e instalar dependencias:

```powershell
# Crear entorno virtual
python -m venv venv
.\venv\Scripts\Activate.ps1  # Windows
# source venv/bin/activate    # Linux/macOS

# Instalar dependencias
pip install bleak==0.21.1
pip install pandas==2.1.4
pip install numpy==1.26.2
pip install matplotlib==3.8.2
pip install scapy==2.5.0
```

**requirements.txt**:
```
bleak==0.21.1
pandas==2.1.4
numpy==1.26.2
matplotlib==3.8.2
scapy==2.5.0
```

#### Arduino IDE y ESP32

**Instalación**:
1. Arduino IDE 2.x: https://www.arduino.cc/en/software
2. Soporte ESP32:
   - File → Preferences → Additional Board Manager URLs:
   - `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`
3. Tools → Board Manager → Instalar "esp32" by Espressif

**Bibliotecas necesarias** (incluidas en ESP32 core):
- BLEDevice
- BLEUtils
- BLEServer
- BLE2902

---

## Reproducibilidad

### Fase 1: Configurar ESP32

#### 1.1. Flashear Dispositivos

**ESP32_P1 (Peripheral sin autenticación)**:
```cpp
// Abrir codigos_ESP32/client.cpp en Arduino IDE
// Tools → Board → ESP32 Dev Module
// Tools → Port → [Seleccionar puerto COM]
// Upload
```

**ESP32_P2 (Peripheral con PIN)**:
```cpp
// Abrir codigos_ESP32/client_Pin.cpp
// Repetir proceso de upload
```

**ESP32_Master (Central)**:
```cpp
// Abrir codigos_ESP32/master.cpp
// Repetir proceso de upload
```

#### 1.2. Verificar Funcionamiento

Abrir Serial Monitor (115200 baud) en cada dispositivo:

**ESP32_P1**: Debe mostrar "Advertising as ESP32_P1"
**ESP32_P2**: Debe mostrar "Advertising as ESP32_P2"
**ESP32_Master**: Debe conectar automáticamente a P1 y P2

### Fase 2: Captura de Tráfico Normal

#### 2.1. Configurar nRF Sniffer

```powershell
# Conectar nRF52840 Dongle
# Wireshark → Capture → Refresh Interfaces
# Seleccionar "nRF Sniffer for Bluetooth LE COM12"
# Configurar:
#   - Follow mode: Enabled
#   - Target MAC: EC:E3:34:B2:E0:C2 (ESP32_P1)
#   - Advertising channels: 37, 38, 39
```

#### 2.2. Capturar Baseline

```powershell
# Iniciar captura en Wireshark (o tshark)
tshark -i COM12 -w baseline_normal.pcapng

# Dejar correr ESP32_Master enviando comandos (5-10 minutos)
# Detener captura
```

### Fase 3: Ejecutar Ataques

#### 3.1. Escaneo y Reconocimiento

```powershell
python ble_scanner.py --target ESP32_P1 --export scan_results.json
```

#### 3.2. Ataque Directo

```powershell
# En una terminal: iniciar captura
tshark -i COM13 -w attack_direct.pcapng

# En otra terminal: ejecutar ataque
python ble_attack_p1.py --target ESP32_P1 --attack full
```

#### 3.3. Secuestro de Conexión

```powershell
# Iniciar captura
tshark -i COM13 -w attack_hijack.pcapng

# Ejecutar hijacking (mantener 5 minutos)
python ble_connection_hijack.py --address EC:E3:34:B2:E0:C2 --duration 300 --keep-alive

# Intentar conectar con ESP32_Master (debe fallar)
```

#### 3.4. Inyección de Payloads

```powershell
# Captura
tshark -i COM13 -w attack_injection.pcapng

# Fuzzing completo
python ble_payload_injection.py --address EC:E3:34:B2:E0:C2 --mode full --log injection.json
```

### Fase 4: Análisis Forense

#### 4.1. Analizar Comandos

```powershell
python analyze_pcap_commands.py baseline_normal.pcapng --export normal_commands.json
python analyze_pcap_commands.py attack_direct.pcapng --export attack_commands.json
```

#### 4.2. Generar Dataset

```powershell
cd dataset
python extract_bluetooth_dataset.py ../attack_direct.pcapng
python analyze_dataset.py
```

#### 4.3. Machine Learning

```powershell
# Ver ejemplo en dataset/example_usage.py (si existe)
# O usar el dataset con tu propio código ML
```

---

## Resultados y Publicaciones

### Artículo RECSI 2025

**Título**: Auditoría de Seguridad en Dispositivos IoT BLE: Técnicas de Sniffing Pasivo y Ataques GATT

**Autores**: [Autores del artículo]

**Resumen**: Este trabajo presenta una metodología completa para auditar la seguridad de dispositivos IoT BLE, combinando técnicas de sniffing pasivo con ataques activos a nivel de protocolo GATT. Se identificaron múltiples vulnerabilidades críticas en dispositivos sin autenticación y con autenticación débil, demostrando la viabilidad de ataques de secuestro de conexión, inyección de comandos maliciosos y exfiltración de credenciales.

**Contribuciones**:
1. Testbed reproducible con dispositivos ESP32
2. Suite de herramientas Python para ataques BLE/GATT
3. Dataset etiquetado de 26K instancias para ML
4. Metodología de análisis forense de tráfico BLE
5. Recomendaciones de seguridad para fabricantes IoT

### Métricas de Detección

Resultados preliminares con Random Forest (100 árboles):

- **Accuracy**: 97.8%
- **Precision (attack)**: 89.3%
- **Recall (attack)**: 91.7%
- **F1-Score (attack)**: 90.5%
- **AUC-ROC**: 0.982

**Features más importantes**:
1. btatt.opcode (importancia: 0.42)
2. inter_arrival_time (importancia: 0.18)
3. frame.len (importancia: 0.12)

---

## Estructura del Repositorio

```
seguridad_BLE_ataques_GATT/
│
├── README.md                          # Este archivo
├── METODOS_MATERIALES.md              # Documentación técnica detallada
│
├── codigos_ESP32/                     # Firmware ESP32
│   ├── client.cpp                     # ESP32_P1 (sin autenticación)
│   ├── client_Pin.cpp                 # ESP32_P2 (con PIN)
│   └── master.cpp                     # ESP32_Master (central)
│
├── dataset/                           # Dataset y análisis
│   ├── bluetooth_gatt_dataset.csv     # Dataset completo
│   ├── extract_bluetooth_dataset.py   # Script de extracción
│   ├── analyze_dataset.py             # Análisis estadístico
│   └── resumen_dataset.md             # Documentación dataset
│
├── ble_scanner.py                     # Fase 1: Escaneo y reconocimiento
├── ble_attack_p1.py                   # Fase 3: Ataque directo
├── ble_connection_hijack.py           # Fase 3: Secuestro de conexión
├── ble_payload_injection.py           # Fase 3: Inyección de payloads
├── analyze_pcap_commands.py           # Fase 2: Análisis forense
│
└── requirements.txt                   # Dependencias Python
```

---

## Referencias

### Documentación Técnica

1. **Bluetooth Core Specification v5.3**
   - Bluetooth SIG, 2021
   - https://www.bluetooth.com/specifications/specs/

2. **nRF Sniffer for Bluetooth LE User Guide**
   - Nordic Semiconductor, 2023
   - https://infocenter.nordicsemi.com/

3. **ESP32 BLE Arduino Library Documentation**
   - Espressif Systems, 2024
   - https://docs.espressif.com/projects/arduino-esp32/

### Artículos Relacionados

1. Jasek, S. (2016). "Gattacking Bluetooth Smart Devices". Black Hat USA.

2. Ryan, M. (2013). "Bluetooth: With Low Energy Comes Low Security". WOOT.

3. Cyr, B., et al. (2014). "Security Analysis of Wearable Fitness Devices (Fitbit)". 

4. Pallavi, S., et al. (2017). "Security Issues in IoT based on BLE Technology".

### Herramientas Citadas

- **Wireshark**: https://www.wireshark.org/
- **Bleak** (Python BLE): https://github.com/hbldh/bleak
- **nRF Connect**: https://www.nordicsemi.com/Products/Development-tools/nrf-connect-for-desktop

---

## Licencia y Uso Ético

Este código y metodología se proporcionan exclusivamente con fines de **investigación académica y educativa**. 

**Advertencia Legal**:
- Ejecutar estos ataques contra dispositivos sin autorización es ilegal.
- Solo usar en entornos controlados con dispositivos propios.
- Los autores no se responsabilizan del uso indebido de este código.

**Uso permitido**:
- Auditorías de seguridad autorizadas
- Investigación académica
- Desarrollo de contramedidas
- Educación en ciberseguridad

---

## Contacto

Para preguntas sobre la investigación, colaboraciones o acceso al artículo completo:

- **Email**: [Email de contacto]
- **Institución**: [Universidad/Centro de investigación]
- **GitHub**: https://github.com/[usuario]/seguridad_BLE_ataques_GATT

---

**Fecha de publicación**: Noviembre 2025  
**Versión**: 1.0  
**Estado**: Artículo aceptado en RECSI 2025
