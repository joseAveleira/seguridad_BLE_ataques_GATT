#!/usr/bin/env python3
"""
Script para extraer características del tráfico Bluetooth GATT y generar un dataset CSV
etiquetado con información de ataques para análisis de anomalías.

Autor: Dataset Generator
Fecha: 2025-11-16
"""

import subprocess
import pandas as pd
import re
from datetime import datetime
import sys

# Configuración de rutas
PCAPNG_FILE = "dataset_Gatt_attacks.pcapng"
TIMESTAMPS_FILE = "attack_timestamps.txt"
OUTPUT_CSV = "bluetooth_gatt_dataset.csv"

def parse_attack_timestamps(filename):
    """
    Parsea el archivo de timestamps de ataques y extrae los rangos temporales.
    
    Returns:
        list: Lista de tuplas (inicio, fin, tipo_ataque)
    """
    attack_ranges = []
    current_attack_start = None
    current_attack_type = None
    
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            # Buscar inicio de ataque
            match_start = re.search(r'\[(\d+\.\d+)\]\s+ATTACK_START:\s+Iniciando ataque \'(\w+)\'', line)
            if match_start:
                current_attack_start = float(match_start.group(1))
                current_attack_type = match_start.group(2)
                continue
            
            # Buscar fin de ataque
            match_end = re.search(r'\[(\d+\.\d+)\]\s+ATTACK_END:', line)
            if match_end and current_attack_start is not None:
                attack_end = float(match_end.group(1))
                attack_ranges.append((current_attack_start, attack_end, current_attack_type))
                current_attack_start = None
                current_attack_type = None
    
    print(f"✓ Encontrados {len(attack_ranges)} períodos de ataque")
    for idx, (start, end, atype) in enumerate(attack_ranges, 1):
        print(f"  Ataque {idx}: {atype} - {start:.3f} a {end:.3f} ({end-start:.3f}s)")
    
    return attack_ranges

def classify_timestamp(timestamp, attack_ranges):
    """
    Clasifica un timestamp como 'attack' o 'normal' basándose en los rangos de ataque.
    
    Args:
        timestamp: Timestamp en formato epoch (float)
        attack_ranges: Lista de tuplas (inicio, fin, tipo_ataque)
    
    Returns:
        str: 'attack' o 'normal'
    """
    for start, end, _ in attack_ranges:
        if start <= timestamp <= end:
            return 'attack'
    return 'normal'

def extract_bluetooth_data():
    """
    Extrae datos del archivo PCAPNG usando tshark.
    
    Returns:
        pd.DataFrame: DataFrame con los datos extraídos
    """
    print("\n🔍 Extrayendo datos del pcapng con tshark...")
    
    # Campos relevantes para análisis de anomalías en Bluetooth GATT:
    # - Información temporal y de frame
    # - Direcciones MAC (dispositivos involucrados)
    # - Tipo de PDU y opcodes ATT
    # - Tamaños de paquete y longitudes
    # - Handles GATT (características específicas)
    
    tshark_fields = [
        "frame.number",                    # Número de frame
        "frame.time_epoch",                # Timestamp epoch
        "frame.len",                       # Longitud total del frame
        "btle.length",                     # Longitud del payload BLE
        "btle.advertising_address",        # Dirección del anunciante
        "btle.central_bd_addr",           # Dirección central (master)
        "btle.peripheral_bd_addr",        # Dirección periférico (slave)
        "btle.access_address",            # Access address
        "btle.advertising_header.pdu_type",  # Tipo de PDU
        "btle.data_header.llid",          # Link Layer ID
        "btatt.opcode",                   # Opcode ATT/GATT
        "btatt.handle",                   # Handle GATT
        "btatt.value",                    # Valor escrito/leído
    ]
    
    # Construir comando tshark
    fields_args = []
    for field in tshark_fields:
        fields_args.extend(["-e", field])
    
    cmd = [
        "tshark",
        "-r", PCAPNG_FILE,
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "occurrence=f"  # Solo primera ocurrencia de campos múltiples
    ] + fields_args
    
    print(f"  Ejecutando: tshark con {len(tshark_fields)} campos...")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, encoding='utf-8')
        
        # Guardar resultado temporal
        temp_csv = "temp_extraction.csv"
        with open(temp_csv, 'w', encoding='utf-8') as f:
            f.write(result.stdout)
        
        # Leer con pandas
        df = pd.read_csv(temp_csv)
        
        print(f"✓ Extraídos {len(df)} paquetes")
        print(f"  Columnas: {list(df.columns)}")
        
        return df
    
    except subprocess.CalledProcessError as e:
        print(f"❌ Error ejecutando tshark: {e}")
        print(f"   stderr: {e.stderr}")
        sys.exit(1)

def filter_relevant_packets(df):
    """
    Filtra paquetes relevantes y elimina tramas irrelevantes.
    
    Args:
        df: DataFrame con todos los paquetes
    
    Returns:
        pd.DataFrame: DataFrame filtrado
    """
    print("\n🔧 Filtrando paquetes relevantes...")
    
    initial_count = len(df)
    
    # Mantener solo paquetes con información ATT/GATT o con direcciones relevantes
    # Eliminar paquetes malformados o sin información útil
    df_filtered = df[
        (df['btatt.opcode'].notna()) |  # Tiene opcode ATT
        (df['btle.central_bd_addr'].notna()) |  # Tiene dirección central
        (df['btle.peripheral_bd_addr'].notna())  # Tiene dirección periférico
    ].copy()
    
    # Eliminar columnas completamente vacías
    df_filtered = df_filtered.dropna(axis=1, how='all')
    
    removed = initial_count - len(df_filtered)
    print(f"✓ Filtrados {len(df_filtered)} paquetes relevantes")
    print(f"  Eliminados {removed} paquetes irrelevantes ({removed/initial_count*100:.1f}%)")
    
    return df_filtered

def create_features(df, attack_ranges):
    """
    Crea características adicionales y etiqueta los datos.
    
    Args:
        df: DataFrame con datos crudos
        attack_ranges: Rangos de ataque
    
    Returns:
        pd.DataFrame: DataFrame con características y etiquetas
    """
    print("\n🏗️  Creando características y etiquetando datos...")
    
    # Convertir opcodes hexadecimales a enteros
    if 'btatt.opcode' in df.columns:
        df['btatt.opcode'] = df['btatt.opcode'].apply(
            lambda x: int(x, 16) if pd.notna(x) and x != '' else -1
        )
    
    # Convertir handles a enteros (tomar el primero si hay múltiples)
    if 'btatt.handle' in df.columns:
        df['btatt.handle'] = df['btatt.handle'].apply(
            lambda x: int(str(x).split(',')[0], 16) if pd.notna(x) and x != '' else -1
        )
    
    # Calcular tiempo entre paquetes (inter-arrival time)
    if 'frame.time_epoch' in df.columns:
        df['frame.time_epoch'] = pd.to_numeric(df['frame.time_epoch'], errors='coerce')
        df['inter_arrival_time'] = df['frame.time_epoch'].diff().fillna(0)
    
    # Clasificar como ataque o normal
    df['type'] = df['frame.time_epoch'].apply(
        lambda ts: classify_timestamp(ts, attack_ranges)
    )
    
    # Estadísticas
    attack_count = (df['type'] == 'attack').sum()
    normal_count = (df['type'] == 'normal').sum()
    
    print(f"✓ Dataset etiquetado:")
    print(f"  - Paquetes normales: {normal_count} ({normal_count/len(df)*100:.1f}%)")
    print(f"  - Paquetes de ataque: {attack_count} ({attack_count/len(df)*100:.1f}%)")
    
    return df

def save_dataset(df, filename):
    """
    Guarda el dataset en formato CSV.
    
    Args:
        df: DataFrame a guardar
        filename: Nombre del archivo de salida
    """
    print(f"\n💾 Guardando dataset en {filename}...")
    
    # Reordenar columnas para que 'type' sea la última
    cols = [col for col in df.columns if col != 'type'] + ['type']
    df = df[cols]
    
    df.to_csv(filename, index=False)
    
    print(f"✓ Dataset guardado exitosamente")
    print(f"  - Tamaño: {len(df)} filas × {len(df.columns)} columnas")
    print(f"  - Archivo: {filename}")

def main():
    """Función principal del script."""
    print("=" * 70)
    print("  EXTRACTOR DE DATASET BLUETOOTH GATT PARA DETECCIÓN DE ANOMALÍAS")
    print("=" * 70)
    
    # 1. Parsear timestamps de ataques
    print("\n[1/5] Parseando timestamps de ataques...")
    attack_ranges = parse_attack_timestamps(TIMESTAMPS_FILE)
    
    # 2. Extraer datos con tshark
    print("\n[2/5] Extrayendo datos del pcapng...")
    df = extract_bluetooth_data()
    
    # 3. Filtrar paquetes relevantes
    print("\n[3/5] Filtrando paquetes relevantes...")
    df_filtered = filter_relevant_packets(df)
    
    # 4. Crear características y etiquetar
    print("\n[4/5] Creando características y etiquetando...")
    df_final = create_features(df_filtered, attack_ranges)
    
    # 5. Guardar dataset
    print("\n[5/5] Guardando dataset...")
    save_dataset(df_final, OUTPUT_CSV)
    
    print("\n" + "=" * 70)
    print("✅ PROCESO COMPLETADO EXITOSAMENTE")
    print("=" * 70)
    print(f"\nEl dataset '{OUTPUT_CSV}' está listo para análisis científico.")
    print("Puedes usarlo con bibliotecas como pandas, scikit-learn, o TensorFlow.")
    print("\nResumen del dataset:")
    print(df_final.groupby('type').size())

if __name__ == "__main__":
    main()
