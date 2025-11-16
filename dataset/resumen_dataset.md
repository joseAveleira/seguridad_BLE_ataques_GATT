# 📊 Proyecto: Extracción de Dataset Bluetooth GATT para Detección de Anomalías

## 🎯 Resumen Ejecutivo

Este proyecto ha creado exitosamente un **dataset estructurado en formato CSV** a partir de capturas de tráfico Bluetooth GATT (`.pcapng`), etiquetado con información sobre ataques para su uso en investigación científica sobre detección de anomalías en dispositivos IoT.

## ✅ Resultados Obtenidos

### Dataset Generado
- **Archivo**: `bluetooth_gatt_dataset.csv`
- **Tamaño**: ~3.1 MB (26,465 instancias)
- **Características**: 12 campos técnicos + 1 etiqueta
- **Balance**: 95.25% normal, 4.75% ataques
- **Formato**: CSV listo para análisis con pandas, scikit-learn, TensorFlow

### Scripts Desarrollados

1. **`extract_bluetooth_dataset.py`** ⭐
   - Extrae datos del pcapng usando tshark
   - Parsea timestamps de ataques
   - Filtra tramas irrelevantes
   - Etiqueta automáticamente cada paquete
   - Genera el CSV final

2. **`analyze_dataset.py`**
   - Análisis estadístico completo
   - Distribución de opcodes ATT/GATT
   - Métricas por clase (normal/attack)
   - Análisis temporal y de dispositivos

3. **`example_usage.py`**
   - 3 ejemplos prácticos de uso
   - Clasificación supervisada (Random Forest)
   - Detección de anomalías (Isolation Forest)
   - Análisis temporal de patrones

4. **`README_DATASET.md`**
   - Documentación completa del dataset
   - Descripción de cada característica
   - Ejemplos de código
   - Guía de citación para artículos

## 📋 Características del Dataset

### Campos Extraídos

| Campo | Descripción | Utilidad |
|-------|-------------|----------|
| `frame.number` | Número de paquete | Orden secuencial |
| `frame.time_epoch` | Timestamp | Análisis temporal |
| `frame.len` | Tamaño del frame | Anomalías de tamaño |
| `btle.length` | Longitud BLE | Características BLE |
| `btle.central_bd_addr` | MAC central | Identificación dispositivos |
| `btle.peripheral_bd_addr` | MAC periférico | Identificación dispositivos |
| `btle.access_address` | Access Address | Contexto del enlace |
| `btle.data_header.llid` | Link Layer ID | Tipo de PDU |
| `btatt.opcode` | Opcode GATT | **CRÍTICO**: Operaciones |
| `btatt.handle` | Handle GATT | Características atacadas |
| `btatt.value` | Valor escrito/leído | Datos de payload |
| `inter_arrival_time` | Tiempo entre paquetes | Patrones temporales |
| **`type`** | **Etiqueta** | **attack / normal** |

### Filtrado Inteligente

El script elimina automáticamente:
- ✅ Tramas sin información ATT/GATT ni direcciones útiles (56.8% filtradas)
- ✅ Paquetes malformados
- ✅ Beacons y advertising irrelevantes
- ✅ Datos duplicados o sin valor analítico

**Resultado**: Solo 26,465 paquetes relevantes de 61,322 originales

## 🔍 Descubrimientos Clave

### Patrones de Ataque Detectados

**Opcodes característicos de ataques**:
- `0x12` Write Request (28.81% en ataques vs. 0% en normal)
- `0x13` Write Response (27.12% en ataques)
- Predominio de operaciones de escritura

**Opcodes típicos de tráfico normal**:
- `0x08` Read By Type Request (17.41%)
- `0x52` Write Command (13.39%)
- Mayor diversidad de operaciones

### Características Temporales

- **Ataques**: Inter-arrival time promedio de 24.5 ms
- **Normal**: Inter-arrival time promedio de 12.7 ms
- **Implicación**: Los ataques son más "lentos" (operaciones más espaciadas)

### Dispositivos Involucrados

- **2 dispositivos centrales** (master):
  - `ec:e3:34:b3:26:ba` (91.5% del tráfico)
  - `00:1a:7d:da:71:13` (8.5% del tráfico)
  
- **1 dispositivo periférico** (slave - atacado):
  - `ec:e3:34:b2:e0:c2` (100% del tráfico)

## 💡 Uso para Artículos Científicos

### Adecuado para:

✅ **Detección de anomalías en IoT**
- Métodos supervisados y no supervisados
- Comparación de algoritmos (RF, SVM, NN)
- Evaluación de métricas en datos desbalanceados

✅ **Análisis de seguridad Bluetooth**
- Patrones de ataque GATT
- Caracterización de comportamiento malicioso
- Estudio de protocolos BLE

✅ **Machine Learning aplicado**
- Feature engineering
- Técnicas de balanceo (SMOTE)
- Validación temporal vs. aleatoria

### Metodología para Paper

1. **Introducción**: Problemas de seguridad en BLE/IoT
2. **Dataset**: Describe este dataset (26K instancias, 12 features)
3. **Características**: Explica los campos técnicos de GATT
4. **Experimentos**: 
   - Baseline: Random Forest / SVM
   - Advanced: Deep Learning (LSTM para secuencias)
   - Detección: Isolation Forest / One-Class SVM
5. **Resultados**: Métricas (Precision, Recall, F1, AUC-ROC)
6. **Conclusiones**: Eficacia de la detección, features importantes

## 🚀 Próximos Pasos Sugeridos

### Para Mejorar el Dataset:

1. **Feature Engineering**:
   - Agregaciones por ventanas temporales
   - Secuencias de opcodes (n-gramas)
   - Estadísticas rolling (mean, std)
   - One-hot encoding de opcodes

2. **Balanceo de Clases**:
   - SMOTE (Synthetic Minority Over-sampling)
   - Undersampling del tráfico normal
   - Class weights en modelos

3. **Nuevas Características**:
   - Tasa de cambio de opcodes
   - Entropía de valores
   - Desviación de patrones normales

### Para Análisis Avanzado:

1. **Deep Learning**:
   - LSTM/GRU para secuencias temporales
   - Autoencoders para detección de anomalías
   - CNN-1D sobre ventanas de paquetes

2. **Ensemble Methods**:
   - Stacking de múltiples modelos
   - Voting classifiers
   - Boosting (XGBoost, LightGBM)

3. **Explainability**:
   - SHAP values
   - LIME para interpretabilidad
   - Feature importance analysis

## 📚 Referencias Técnicas

### Herramientas Utilizadas:
- **tshark**: Análisis de pcapng
- **Python 3**: Procesamiento de datos
- **Pandas**: Manipulación de datos
- **scikit-learn**: Machine Learning

### Protocolos Implementados:
- **BLE (Bluetooth Low Energy)**: Capa física
- **GATT (Generic Attribute Profile)**: Capa de aplicación
- **ATT (Attribute Protocol)**: Protocolo subyacente

## 📧 Contacto y Soporte

Para preguntas sobre el dataset o colaboraciones:
- GitHub: [Tu perfil]
- Email: [Tu email]
- Institución: [Tu universidad/empresa]

## 📝 Licencia

Este dataset y scripts asociados están disponibles para uso académico y de investigación.

---

**Proyecto completado**: 16 de noviembre de 2025  
**Versión**: 1.0  
**Estado**: ✅ Listo para publicación
