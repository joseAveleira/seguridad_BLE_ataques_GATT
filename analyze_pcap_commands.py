#!/usr/bin/env python3
"""
Analizador de Comandos BLE desde PCAP - Fase 2
===============================================

Extrae y analiza comandos GATT Write desde archivos PCAP capturados
con Wireshark/nRF Sniffer. Identifica vulnerabilidades y comandos
enviados entre Master y ESP32.

USO:
    python analyze_pcap_commands.py comandosbatt.pcapng
    python analyze_pcap_commands.py comandosbatt.pcapng --export resultados.json
    python analyze_pcap_commands.py comandosbatt.pcapng --verbose

DEPENDENCIAS:
    - tshark instalado
"""

import subprocess
import json
import sys
import argparse
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Optional

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    BLUE = '\033[94m'
    END = '\033[0m'
    BOLD = '\033[1m'

class PCAPAnalyzer:
    def __init__(self, pcap_file: str, verbose: bool = False):
        self.pcap_file = pcap_file
        self.verbose = verbose
        
        # Comandos conocidos del ESP32
        self.known_commands = {
            0x01: "SET_MODE",
            0x02: "SET_LED", 
            0x03: "SET_BRIGHTNESS",
            0x04: "SET_TIMER",
            0x05: "RESET",
            0x10: "AUTH_REQUEST"
        }
        
        self.results = {
            "pcap_file": pcap_file,
            "analysis_timestamp": datetime.now().isoformat(),
            "total_packets": 0,
            "att_packets": 0,
            "commands": [],
            "vulnerabilities": [],
            "unique_commands": set(),
            "command_stats": defaultdict(int)
        }
    
    def print_banner(self):
        print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}Análisis de Comandos BLE desde PCAP{Colors.END}")
        print(f"{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"Archivo: {self.pcap_file}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Colors.CYAN}{'='*70}{Colors.END}\n")
    
    def extract_att_packets(self) -> List[Dict]:
        """Extraer paquetes ATT con tshark"""
        print(f"{Colors.YELLOW}[*] Extrayendo paquetes ATT Write Commands del PCAP...{Colors.END}")
        
        # Filtrar específicamente Write Commands (0x52) con valores
        cmd = [
            "tshark",
            "-r", self.pcap_file,
            "-Y", "btatt.opcode == 0x52",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time_relative",
            "-e", "btatt.opcode",
            "-e", "btatt.opcode.method",
            "-e", "btatt.handle",
            "-e", "btatt.value",
            "-E", "separator=|"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            packets = []
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                    
                parts = line.split('|')
                if len(parts) >= 6:
                    packet = {
                        "frame": parts[0],
                        "time": parts[1],
                        "opcode": parts[2],
                        "method": parts[3] if len(parts) > 3 else "",
                        "handle": parts[4] if len(parts) > 4 else "",
                        "value": parts[5] if len(parts) > 5 else ""
                    }
                    packets.append(packet)
                    self.results["att_packets"] += 1
            
            print(f"{Colors.GREEN}[+] Encontrados {len(packets)} paquetes ATT{Colors.END}")
            return packets
            
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}[!] Error ejecutando tshark: {e}{Colors.END}")
            return []
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.END}")
            return []
    
    def parse_command(self, value_hex: str) -> Optional[Dict]:
        """Parsear valor hex y extraer comando"""
        if not value_hex:
            return None
        
        try:
            # Remover espacios y convertir
            value_clean = value_hex.replace(":", "").replace(" ", "")
            if len(value_clean) < 2:
                return None
            
            # Obtener byte de comando
            cmd_byte = int(value_clean[0:2], 16)
            
            if cmd_byte not in self.known_commands:
                return None
            
            cmd_name = self.known_commands[cmd_byte]
            
            # Extraer bytes de datos
            data_bytes = []
            for i in range(0, len(value_clean), 2):
                data_bytes.append(int(value_clean[i:i+2], 16))
            
            command_info = {
                "command": cmd_name,
                "cmd_byte": f"0x{cmd_byte:02X}",
                "hex": value_hex,
                "bytes": data_bytes
            }
            
            # Análisis específico por comando
            if cmd_byte == 0x10 and len(data_bytes) >= 6:
                # AUTH_REQUEST - buscar PIN
                pin_bytes = data_bytes[1:]
                pin_ascii = ''.join(chr(b) for b in pin_bytes if 32 <= b <= 126)
                command_info["pin_ascii"] = pin_ascii
                command_info["pin_hex"] = ''.join(f'{b:02X}' for b in pin_bytes)
                
            elif cmd_byte == 0x03 and len(data_bytes) > 1:
                # SET_BRIGHTNESS
                brightness = data_bytes[1]
                command_info["brightness"] = brightness
                
            elif cmd_byte == 0x01 and len(data_bytes) > 1:
                # SET_MODE
                mode = data_bytes[1]
                mode_name = "ECO" if mode == 0 else "TURBO" if mode == 1 else f"UNKNOWN({mode})"
                command_info["mode"] = mode_name
                
            elif cmd_byte == 0x04 and len(data_bytes) > 1:
                # SET_TIMER
                timer_min = data_bytes[1]
                command_info["timer_minutes"] = timer_min
            
            return command_info
            
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] Error parseando comando: {e}{Colors.END}")
            return None
    
    def analyze_vulnerabilities(self):
        """Análisis de vulnerabilidades detectadas"""
        print(f"\n{Colors.YELLOW}[*] Analizando vulnerabilidades...{Colors.END}\n")
        
        vulns = []
        
        # VULN-01: Comandos sin autenticación
        write_commands = [c for c in self.results["commands"] if c["command"] != "AUTH_REQUEST"]
        if write_commands:
            vuln = {
                "id": "VULN-01",
                "severity": "HIGH",
                "title": "Comandos GATT sin autenticación",
                "description": f"Se detectaron {len(write_commands)} comandos Write sin autenticación previa",
                "impact": "Cualquier dispositivo puede enviar comandos al ESP32",
                "commands": [c["command"] for c in write_commands]
            }
            vulns.append(vuln)
            print(f"{Colors.RED}[VULN-01] {vuln['title']}{Colors.END}")
            print(f"  Comandos detectados: {len(write_commands)}")
        
        # VULN-02: PIN en texto plano
        auth_commands = [c for c in self.results["commands"] if c["command"] == "AUTH_REQUEST"]
        for cmd in auth_commands:
            if "pin_ascii" in cmd and cmd["pin_ascii"]:
                vuln = {
                    "id": "VULN-02",
                    "severity": "CRITICAL",
                    "title": "PIN transmitido en texto plano",
                    "description": f"PIN detectado: {cmd['pin_ascii']}",
                    "impact": "El PIN puede ser interceptado fácilmente",
                    "pin": cmd["pin_ascii"],
                    "hex": cmd["pin_hex"]
                }
                vulns.append(vuln)
                print(f"{Colors.RED}[VULN-02] {vuln['title']}{Colors.END}")
                print(f"  PIN: {cmd['pin_ascii']} (hex: {cmd['pin_hex']})")
        
        # VULN-03: DoS mediante comandos
        dos_commands = [c for c in self.results["commands"] 
                       if (c["command"] == "SET_BRIGHTNESS" and c.get("brightness") == 0) or
                          c["command"] == "RESET"]
        if dos_commands:
            vuln = {
                "id": "VULN-03",
                "severity": "MEDIUM",
                "title": "Vectores de Denial of Service",
                "description": f"Se detectaron {len(dos_commands)} comandos potencialmente DoS",
                "impact": "Puede inutilizar el dispositivo",
                "commands": [c["command"] for c in dos_commands]
            }
            vulns.append(vuln)
            print(f"{Colors.YELLOW}[VULN-03] {vuln['title']}{Colors.END}")
            print(f"  Comandos DoS: {len(dos_commands)}")
        
        self.results["vulnerabilities"] = vulns
    
    def analyze(self):
        """Análisis completo del PCAP"""
        self.print_banner()
        
        # Extraer paquetes ATT
        packets = self.extract_att_packets()
        self.results["total_packets"] = len(packets)
        
        if not packets:
            print(f"{Colors.RED}[!] No se encontraron paquetes ATT en el PCAP{Colors.END}")
            print(f"{Colors.YELLOW}[i] Verifica que:{Colors.END}")
            print(f"  - La captura se hizo con Follow configurado en Wireshark")
            print(f"  - El Master envió comandos durante la captura")
            return
        
        # Analizar comandos
        print(f"\n{Colors.YELLOW}[*] Analizando comandos GATT...{Colors.END}\n")
        
        for packet in packets:
            if not packet["value"]:
                continue
            
            cmd_info = self.parse_command(packet["value"])
            if cmd_info:
                cmd_info["frame"] = packet["frame"]
                cmd_info["time"] = packet["time"]
                cmd_info["handle"] = packet["handle"]
                
                self.results["commands"].append(cmd_info)
                self.results["unique_commands"].add(cmd_info["command"])
                self.results["command_stats"][cmd_info["command"]] += 1
                
                # Mostrar comando
                color = Colors.MAGENTA if cmd_info["command"] != "AUTH_REQUEST" else Colors.RED
                print(f"{color}[Frame {packet['frame']}]{Colors.END} {cmd_info['command']}: {cmd_info['hex']}")
                
                if cmd_info["command"] == "SET_BRIGHTNESS" and "brightness" in cmd_info:
                    print(f"  → Brillo: {cmd_info['brightness']}")
                elif cmd_info["command"] == "SET_MODE" and "mode" in cmd_info:
                    print(f"  → Modo: {cmd_info['mode']}")
                elif cmd_info["command"] == "SET_TIMER" and "timer_minutes" in cmd_info:
                    print(f"  → Timer: {cmd_info['timer_minutes']} min")
                elif cmd_info["command"] == "AUTH_REQUEST" and "pin_ascii" in cmd_info:
                    print(f"  → PIN: {cmd_info['pin_ascii']}")
        
        # Análisis de vulnerabilidades
        self.analyze_vulnerabilities()
        
        # Resumen
        print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}RESUMEN DEL ANÁLISIS{Colors.END}")
        print(f"{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"Total paquetes ATT: {self.results['att_packets']}")
        print(f"Comandos detectados: {len(self.results['commands'])}")
        print(f"Tipos de comandos únicos: {len(self.results['unique_commands'])}")
        print(f"Vulnerabilidades: {len(self.results['vulnerabilities'])}")
        
        print(f"\n{Colors.BOLD}Estadísticas de comandos:{Colors.END}")
        for cmd, count in sorted(self.results["command_stats"].items(), key=lambda x: x[1], reverse=True):
            print(f"  {cmd}: {count}")
        
        print(f"{Colors.CYAN}{'='*70}{Colors.END}\n")
    
    def export_results(self, output_file: str):
        """Exportar resultados a JSON"""
        # Convertir set a list para JSON
        self.results["unique_commands"] = list(self.results["unique_commands"])
        self.results["command_stats"] = dict(self.results["command_stats"])
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"{Colors.GREEN}[+] Resultados exportados a: {output_file}{Colors.END}")

def main():
    parser = argparse.ArgumentParser(description="Analizar comandos BLE desde archivo PCAP")
    parser.add_argument("pcap", help="Archivo PCAP/PCAPNG a analizar")
    parser.add_argument("--export", "-e", help="Exportar resultados a JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Modo verbose")
    
    args = parser.parse_args()
    
    analyzer = PCAPAnalyzer(args.pcap, verbose=args.verbose)
    analyzer.analyze()
    
    if args.export:
        analyzer.export_results(args.export)

if __name__ == "__main__":
    main()
