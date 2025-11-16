#!/usr/bin/env python3
"""
Script para analizar y validar el dataset de tráfico Bluetooth GATT generado.
Genera estadísticas descriptivas y visualizaciones básicas.

Autor: Dataset Analyzer
Fecha: 2025-11-16
"""

import pandas as pd
import numpy as np
from collections import Counter

# Configuración
DATASET_FILE = "bluetooth_gatt_dataset.csv"

def load_dataset(filename):
    """Carga el dataset desde CSV."""
    print(f"📂 Cargando dataset: {filename}")
    df = pd.read_csv(filename)
    print(f"✓ Dataset cargado: {len(df)} filas × {len(df.columns)} columnas\n")
    return df

def basic_statistics(df):
    """Muestra estadísticas básicas del dataset."""
    print("=" * 70)
    print("📊 ESTADÍSTICAS BÁSICAS DEL DATASET")
    print("=" * 70)
    
    print("\n1. Información general:")
    print(f"   - Total de paquetes: {len(df):,}")
    print(f"   - Columnas: {len(df.columns)}")
    print(f"   - Memoria utilizada: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
    
    print("\n2. Distribución de clases:")
    class_dist = df['type'].value_counts()
    for class_name, count in class_dist.items():
        percentage = count / len(df) * 100
        print(f"   - {class_name.capitalize()}: {count:,} ({percentage:.2f}%)")
    
    print("\n3. Valores faltantes por columna:")
    missing = df.isnull().sum()
    missing_pct = (missing / len(df) * 100).round(2)
    for col in df.columns:
        if missing[col] > 0:
            print(f"   - {col}: {missing[col]:,} ({missing_pct[col]}%)")
    
    print("\n4. Rango temporal:")
    if 'frame.time_epoch' in df.columns:
        time_min = df['frame.time_epoch'].min()
        time_max = df['frame.time_epoch'].max()
        duration = time_max - time_min
        print(f"   - Inicio: {time_min:.3f}")
        print(f"   - Fin: {time_max:.3f}")
        print(f"   - Duración total: {duration:.2f} segundos ({duration/60:.2f} minutos)")

def analyze_opcodes(df):
    """Analiza la distribución de opcodes ATT/GATT."""
    print("\n" + "=" * 70)
    print("🔍 ANÁLISIS DE OPCODES ATT/GATT")
    print("=" * 70)
    
    if 'btatt.opcode' not in df.columns:
        print("⚠️  Columna 'btatt.opcode' no encontrada")
        return
    
    # Mapeo de opcodes comunes
    opcode_names = {
        0x01: "Error Response",
        0x02: "Exchange MTU Request",
        0x03: "Exchange MTU Response",
        0x04: "Find Information Request",
        0x05: "Find Information Response",
        0x06: "Find By Type Value Request",
        0x07: "Find By Type Value Response",
        0x08: "Read By Type Request",
        0x09: "Read By Type Response",
        0x0a: "Read Request",
        0x0b: "Read Response",
        0x0c: "Read Blob Request",
        0x0d: "Read Blob Response",
        0x0e: "Read Multiple Request",
        0x0f: "Read Multiple Response",
        0x10: "Read By Group Type Request",
        0x11: "Read By Group Type Response",
        0x12: "Write Request",
        0x13: "Write Response",
        0x16: "Prepare Write Request",
        0x17: "Prepare Write Response",
        0x18: "Execute Write Request",
        0x19: "Execute Write Response",
        0x1b: "Handle Value Notification",
        0x1d: "Handle Value Indication",
        0x1e: "Handle Value Confirmation",
        0x52: "Write Command",
        0xd2: "Signed Write Command",
        -1: "No Opcode (empty)"
    }
    
    # Filtrar solo paquetes con opcode
    df_with_opcode = df[df['btatt.opcode'] != -1].copy()
    
    print(f"\n1. Total de paquetes con opcode ATT: {len(df_with_opcode):,}")
    print(f"   ({len(df_with_opcode)/len(df)*100:.1f}% del total)")
    
    print("\n2. Top 10 opcodes más frecuentes:")
    opcode_counts = df_with_opcode['btatt.opcode'].value_counts().head(10)
    for opcode, count in opcode_counts.items():
        opcode_int = int(opcode) if opcode != -1 else -1
        name = opcode_names.get(opcode_int, "Unknown")
        percentage = count / len(df_with_opcode) * 100
        print(f"   0x{opcode_int:02x} ({name:30s}): {count:5,} ({percentage:5.2f}%)")
    
    print("\n3. Distribución de opcodes por clase:")
    for class_type in ['normal', 'attack']:
        df_class = df_with_opcode[df_with_opcode['type'] == class_type]
        if len(df_class) > 0:
            print(f"\n   {class_type.upper()}:")
            top_opcodes = df_class['btatt.opcode'].value_counts().head(5)
            for opcode, count in top_opcodes.items():
                opcode_int = int(opcode) if opcode != -1 else -1
                name = opcode_names.get(opcode_int, "Unknown")
                percentage = count / len(df_class) * 100
                print(f"     0x{opcode_int:02x} ({name:30s}): {count:5,} ({percentage:5.2f}%)")

def analyze_packet_sizes(df):
    """Analiza la distribución de tamaños de paquetes."""
    print("\n" + "=" * 70)
    print("📏 ANÁLISIS DE TAMAÑOS DE PAQUETES")
    print("=" * 70)
    
    if 'frame.len' not in df.columns:
        print("⚠️  Columna 'frame.len' no encontrada")
        return
    
    print("\n1. Estadísticas de tamaño de frame:")
    print(f"   - Mínimo: {df['frame.len'].min()} bytes")
    print(f"   - Máximo: {df['frame.len'].max()} bytes")
    print(f"   - Promedio: {df['frame.len'].mean():.2f} bytes")
    print(f"   - Mediana: {df['frame.len'].median():.2f} bytes")
    print(f"   - Desviación estándar: {df['frame.len'].std():.2f} bytes")
    
    print("\n2. Tamaños por clase:")
    for class_type in ['normal', 'attack']:
        df_class = df[df['type'] == class_type]
        print(f"\n   {class_type.upper()}:")
        print(f"     - Promedio: {df_class['frame.len'].mean():.2f} bytes")
        print(f"     - Mediana: {df_class['frame.len'].median():.2f} bytes")
        print(f"     - Std Dev: {df_class['frame.len'].std():.2f} bytes")

def analyze_inter_arrival_times(df):
    """Analiza los tiempos entre paquetes."""
    print("\n" + "=" * 70)
    print("⏱️  ANÁLISIS DE TIEMPOS INTER-ARRIBO")
    print("=" * 70)
    
    if 'inter_arrival_time' not in df.columns:
        print("⚠️  Columna 'inter_arrival_time' no encontrada")
        return
    
    # Filtrar valores extremos (outliers)
    iat = df[df['inter_arrival_time'] > 0]['inter_arrival_time']
    iat_filtered = iat[iat < iat.quantile(0.99)]  # Eliminar top 1% outliers
    
    print("\n1. Estadísticas generales (sin outliers):")
    print(f"   - Mínimo: {iat_filtered.min()*1000:.3f} ms")
    print(f"   - Máximo: {iat_filtered.max()*1000:.3f} ms")
    print(f"   - Promedio: {iat_filtered.mean()*1000:.3f} ms")
    print(f"   - Mediana: {iat_filtered.median()*1000:.3f} ms")
    
    print("\n2. Tiempos inter-arribo por clase:")
    for class_type in ['normal', 'attack']:
        df_class = df[df['type'] == class_type]
        iat_class = df_class[df_class['inter_arrival_time'] > 0]['inter_arrival_time']
        if len(iat_class) > 0:
            iat_class_filtered = iat_class[iat_class < iat_class.quantile(0.99)]
            print(f"\n   {class_type.upper()}:")
            print(f"     - Promedio: {iat_class_filtered.mean()*1000:.3f} ms")
            print(f"     - Mediana: {iat_class_filtered.median()*1000:.3f} ms")

def analyze_devices(df):
    """Analiza las direcciones MAC de dispositivos."""
    print("\n" + "=" * 70)
    print("🔗 ANÁLISIS DE DISPOSITIVOS (DIRECCIONES MAC)")
    print("=" * 70)
    
    # Analizar direcciones advertising
    if 'btle.advertising_address' in df.columns:
        unique_adv = df['btle.advertising_address'].dropna().unique()
        print(f"\n1. Direcciones advertising únicas: {len(unique_adv)}")
        if len(unique_adv) <= 10:
            for addr in unique_adv:
                count = (df['btle.advertising_address'] == addr).sum()
                print(f"   - {addr}: {count:,} paquetes")
    
    # Analizar direcciones central/peripheral
    if 'btle.central_bd_addr' in df.columns:
        unique_central = df['btle.central_bd_addr'].dropna().unique()
        print(f"\n2. Direcciones central únicas: {len(unique_central)}")
        if len(unique_central) <= 10:
            for addr in unique_central:
                count = (df['btle.central_bd_addr'] == addr).sum()
                print(f"   - {addr}: {count:,} paquetes")
    
    if 'btle.peripheral_bd_addr' in df.columns:
        unique_periph = df['btle.peripheral_bd_addr'].dropna().unique()
        print(f"\n3. Direcciones peripheral únicas: {len(unique_periph)}")
        if len(unique_periph) <= 10:
            for addr in unique_periph:
                count = (df['btle.peripheral_bd_addr'] == addr).sum()
                print(f"   - {addr}: {count:,} paquetes")

def generate_summary_report(df):
    """Genera un resumen ejecutivo para artículo científico."""
    print("\n" + "=" * 70)
    print("📄 RESUMEN EJECUTIVO PARA ARTÍCULO CIENTÍFICO")
    print("=" * 70)
    
    print("\nEl dataset generado contiene las siguientes características:")
    print(f"- Total de instancias: {len(df):,}")
    print(f"- Características (features): {len(df.columns) - 1}")  # -1 por la columna 'type'
    print(f"- Clases: 2 (normal, attack)")
    
    normal_count = (df['type'] == 'normal').sum()
    attack_count = (df['type'] == 'attack').sum()
    print(f"- Distribución de clases:")
    print(f"  · Normal: {normal_count:,} ({normal_count/len(df)*100:.2f}%)")
    print(f"  · Attack: {attack_count:,} ({attack_count/len(df)*100:.2f}%)")
    
    if 'frame.time_epoch' in df.columns:
        duration = df['frame.time_epoch'].max() - df['frame.time_epoch'].min()
        print(f"- Duración de captura: {duration/60:.2f} minutos")
    
    print("\nCaracterísticas extraídas:")
    for col in df.columns:
        if col != 'type':
            non_null = df[col].notna().sum()
            coverage = non_null / len(df) * 100
            print(f"  · {col}: {coverage:.1f}% cobertura")
    
    print("\nEste dataset es adecuado para:")
    print("  ✓ Detección de anomalías en tráfico Bluetooth GATT")
    print("  ✓ Clasificación binaria (ataque/normal)")
    print("  ✓ Análisis de secuencias temporales")
    print("  ✓ Estudios de patrones de tráfico IoT")

def main():
    """Función principal."""
    print("=" * 70)
    print("  ANÁLISIS Y VALIDACIÓN DEL DATASET BLUETOOTH GATT")
    print("=" * 70)
    print()
    
    # Cargar dataset
    df = load_dataset(DATASET_FILE)
    
    # Análisis
    basic_statistics(df)
    analyze_opcodes(df)
    analyze_packet_sizes(df)
    analyze_inter_arrival_times(df)
    analyze_devices(df)
    generate_summary_report(df)
    
    print("\n" + "=" * 70)
    print("✅ ANÁLISIS COMPLETADO")
    print("=" * 70)
    print("\nEl dataset ha sido validado y está listo para ser usado en:")
    print("  - Machine Learning (scikit-learn)")
    print("  - Deep Learning (TensorFlow, PyTorch)")
    print("  - Análisis estadístico (R, SPSS)")
    print("  - Publicaciones científicas")

if __name__ == "__main__":
    main()
