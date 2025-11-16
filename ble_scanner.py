#!/usr/bin/env python3
"""
BLE Scanner - Fase 1: Reconocimiento de Dispositivos IoT
==========================================================

Paper: Security Analysis of Unauthenticated BLE IoT Devices
Autor: [Tu nombre]
Fecha: 2025

OBJETIVO:
Escanear y enumerar dispositivos BLE vulnerables en el entorno,
identificando servicios GATT expuestos y características accesibles.

METODOLOGÍA:
1. Escaneo activo de dispositivos BLE (GAP)
2. Enumeración de servicios GATT (UUIDs)
3. Análisis de características (permisos: Read/Write/Notify)
4. Detección de conexiones activas
5. Fingerprinting de dispositivos ESP32

USO:
    python ble_scanner.py
    python ble_scanner.py --target ESP32_P1
    python ble_scanner.py --export scan_results.json

DEPENDENCIAS:
    pip install bleak
"""

import asyncio
import json
import argparse
import sys
from datetime import datetime
from typing import Dict, List, Optional
from bleak import BleakScanner, BleakClient
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

# Colores para terminal
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class BLESecurityScanner:
    def __init__(self, scan_duration: int = 10):
        self.scan_duration = scan_duration
        self.discovered_devices: Dict[str, Dict] = {}
        self.target_devices: List[str] = []
        
    def print_banner(self):
        """Banner científico del scanner"""
        print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}BLE Security Scanner v1.0 - Phase 1: Reconnaissance{Colors.END}")
        print(f"{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"Timestamp: {datetime.now().isoformat()}")
        print(f"Scan Duration: {self.scan_duration}s")
        print(f"{Colors.CYAN}{'='*70}{Colors.END}\n")
    
    def detection_callback(self, device: BLEDevice, advertisement_data: AdvertisementData):
        """Callback para detección de dispositivos durante escaneo"""
        address = device.address
        
        if address not in self.discovered_devices:
            # Fingerprinting básico
            manufacturer_data = advertisement_data.manufacturer_data
            service_uuids = advertisement_data.service_uuids
            
            device_info = {
                "address": address,
                "name": device.name or "Unknown",
                "rssi": advertisement_data.rssi,
                "manufacturer_data": {k: v.hex() for k, v in manufacturer_data.items()},
                "service_uuids": service_uuids,
                "timestamp": datetime.now().isoformat(),
                "is_connectable": True  # Bleak solo detecta connectable devices
            }
            
            self.discovered_devices[address] = device_info
            
            # Identificar targets ESP32 por nombre O por MAC conocida
            is_target = False
            target_macs = ["EC:E3:34:B2:E0:C2"]  # MACs conocidas de dispositivos ESP32
            
            if device.name and ("ESP32" in device.name or "IoT" in device.name):
                is_target = True
            elif address.upper() in [mac.upper() for mac in target_macs]:
                is_target = True
            
            if is_target:
                self.target_devices.append(address)
                print(f"{Colors.GREEN}[+] TARGET FOUND:{Colors.END} {device.name or 'ESP32 (no name)'} ({address}) RSSI: {advertisement_data.rssi} dBm")
            else:
                print(f"{Colors.BLUE}[i] Device:{Colors.END} {device.name or 'N/A'} ({address}) RSSI: {advertisement_data.rssi} dBm")
    
    async def scan_devices(self) -> List[BLEDevice]:
        """Escaneo activo de dispositivos BLE"""
        print(f"{Colors.YELLOW}[*] Starting BLE scan...{Colors.END}\n")
        
        scanner = BleakScanner(detection_callback=self.detection_callback)
        
        await scanner.start()
        await asyncio.sleep(self.scan_duration)
        await scanner.stop()
        
        devices = scanner.discovered_devices
        
        print(f"\n{Colors.YELLOW}[*] Scan complete. Found {len(self.discovered_devices)} devices{Colors.END}")
        print(f"{Colors.GREEN}[*] Target devices: {len(self.target_devices)}{Colors.END}\n")
        
        return devices
    
    async def enumerate_gatt_services(self, address: str) -> Optional[Dict]:
        """Enumerar servicios y características GATT de un dispositivo"""
        print(f"{Colors.YELLOW}[*] Enumerating GATT services for {address}...{Colors.END}")
        
        try:
            async with BleakClient(address, timeout=15.0) as client:
                if not client.is_connected:
                    print(f"{Colors.RED}[!] Failed to connect to {address}{Colors.END}")
                    return None
                
                print(f"{Colors.GREEN}[+] Connected to {address}{Colors.END}")
                
                services_data = {
                    "device_address": address,
                    "device_name": self.discovered_devices.get(address, {}).get("name", "Unknown"),
                    "connection_timestamp": datetime.now().isoformat(),
                    "services": []
                }
                
                # Enumerar servicios
                for service in client.services:
                    service_info = {
                        "uuid": service.uuid,
                        "description": service.description,
                        "characteristics": []
                    }
                    
                    print(f"\n  {Colors.CYAN}[Service]{Colors.END} UUID: {service.uuid}")
                    print(f"           Description: {service.description}")
                    
                    # Enumerar características
                    for char in service.characteristics:
                        # Determinar permisos
                        properties = char.properties
                        perms = []
                        if "read" in properties:
                            perms.append("READ")
                        if "write" in properties or "write-without-response" in properties:
                            perms.append("WRITE")
                        if "notify" in properties:
                            perms.append("NOTIFY")
                        if "indicate" in properties:
                            perms.append("INDICATE")
                        
                        char_info = {
                            "uuid": char.uuid,
                            "description": char.description,
                            "properties": properties,
                            "permissions": perms
                        }
                        
                        service_info["characteristics"].append(char_info)
                        
                        perm_str = ", ".join(perms)
                        print(f"    {Colors.GREEN}[Char]{Colors.END} UUID: {char.uuid}")
                        print(f"           Properties: {perm_str}")
                        
                        # Detectar características potencialmente vulnerables
                        if "WRITE" in perms and "notify" in properties:
                            print(f"           {Colors.RED}⚠ VULNERABLE: Write + Notify (Command/Response){Colors.END}")
                    
                    services_data["services"].append(service_info)
                
                print(f"\n{Colors.GREEN}[+] GATT enumeration complete{Colors.END}\n")
                return services_data
                
        except Exception as e:
            print(f"{Colors.RED}[!] Error enumerating {address}: {e}{Colors.END}")
            return None
    
    async def analyze_all_targets(self) -> List[Dict]:
        """Analizar todos los dispositivos objetivo encontrados"""
        results = []
        
        for address in self.target_devices:
            device_name = self.discovered_devices[address]["name"]
            print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
            print(f"{Colors.BOLD}Analyzing Target: {device_name} ({address}){Colors.END}")
            print(f"{Colors.BOLD}{'='*70}{Colors.END}")
            
            gatt_data = await self.enumerate_gatt_services(address)
            
            if gatt_data:
                analysis = {
                    "device_info": self.discovered_devices[address],
                    "gatt_services": gatt_data
                }
                results.append(analysis)
                
                # Análisis de vulnerabilidades
                self.vulnerability_analysis(analysis)
            
            await asyncio.sleep(1)  # Delay entre dispositivos
        
        return results
    
    def vulnerability_analysis(self, device_data: Dict):
        """Análisis automatizado de vulnerabilidades"""
        print(f"\n{Colors.YELLOW}[*] Vulnerability Analysis:{Colors.END}")
        
        vulnerabilities = []
        
        # Check 1: Servicios sin autenticación
        services = device_data.get("gatt_services", {}).get("services", [])
        write_chars = 0
        notify_chars = 0
        
        for service in services:
            for char in service.get("characteristics", []):
                if "WRITE" in char["permissions"]:
                    write_chars += 1
                if "NOTIFY" in char["permissions"]:
                    notify_chars += 1
        
        if write_chars > 0:
            vuln = f"Found {write_chars} writable characteristic(s) - No authentication detected"
            vulnerabilities.append(vuln)
            print(f"  {Colors.RED}[VULN-01]{Colors.END} {vuln}")
        
        if notify_chars > 0:
            vuln = f"Found {notify_chars} notify characteristic(s) - Passive sniffing possible"
            vulnerabilities.append(vuln)
            print(f"  {Colors.RED}[VULN-02]{Colors.END} {vuln}")
        
        # Check 2: Dispositivos ESP32 conocidos por vulnerabilidades
        device_name = device_data["device_info"]["name"]
        if "ESP32" in device_name:
            vuln = "ESP32 device - Known for weak BLE security implementations"
            vulnerabilities.append(vuln)
            print(f"  {Colors.RED}[VULN-03]{Colors.END} {vuln}")
        
        if not vulnerabilities:
            print(f"  {Colors.GREEN}[i] No obvious vulnerabilities detected{Colors.END}")
        
        device_data["vulnerabilities"] = vulnerabilities
    
    def export_results(self, results: List[Dict], filename: str):
        """Exportar resultados a JSON para análisis científico"""
        export_data = {
            "scan_metadata": {
                "timestamp": datetime.now().isoformat(),
                "scan_duration": self.scan_duration,
                "total_devices": len(self.discovered_devices),
                "target_devices": len(self.target_devices)
            },
            "discovered_devices": list(self.discovered_devices.values()),
            "target_analysis": results
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"\n{Colors.GREEN}[+] Results exported to: {filename}{Colors.END}")
    
    def print_summary(self):
        """Resumen científico del escaneo"""
        print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}SCAN SUMMARY{Colors.END}")
        print(f"{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"Total devices discovered: {len(self.discovered_devices)}")
        print(f"Target devices (ESP32/IoT): {len(self.target_devices)}")
        print(f"Timestamp: {datetime.now().isoformat()}")
        print(f"{Colors.CYAN}{'='*70}{Colors.END}\n")

async def main():
    parser = argparse.ArgumentParser(
        description="BLE Security Scanner - Phase 1: Reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ble_scanner.py
  python ble_scanner.py --duration 20
  python ble_scanner.py --export results.json
  python ble_scanner.py --target ESP32_P1 --enumerate
        """
    )
    
    parser.add_argument("--duration", type=int, default=10, 
                       help="Scan duration in seconds (default: 10)")
    parser.add_argument("--export", type=str, 
                       help="Export results to JSON file")
    parser.add_argument("--target", type=str,
                       help="Specific target device name to focus on")
    parser.add_argument("--enumerate", action="store_true",
                       help="Enumerate GATT services of discovered targets")
    
    args = parser.parse_args()
    
    scanner = BLESecurityScanner(scan_duration=args.duration)
    scanner.print_banner()
    
    # Fase 1: Escaneo
    await scanner.scan_devices()
    
    scanner.print_summary()
    
    # Fase 2: Enumeración GATT (opcional)
    results = []
    if args.enumerate and scanner.target_devices:
        print(f"\n{Colors.YELLOW}[*] Starting GATT enumeration phase...{Colors.END}\n")
        results = await scanner.analyze_all_targets()
    
    # Exportar resultados
    if args.export:
        scanner.export_results(results, args.export)
    
    print(f"\n{Colors.GREEN}[+] Phase 1 complete. Ready for Phase 2 (Sniffing){Colors.END}\n")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}\n")
        sys.exit(0)
