# Deteccion de Ataques DDoS con Machine Learning

## Simulacion Practica — Examen Semestral IA Aplicada a la Ciberseguridad

**Universidad Tecnologica de Panama**  
**Licenciatura en Ciberseguridad**  
**Asignatura: IA Aplicada a la Ciberseguridad — I Semestre 2026**  
**Profesora: Ana Villarreal**

---

## Descripcion del Proyecto

Este proyecto implementa un sistema de deteccion y clasificacion de ataques DDoS (Distributed Denial of Service) utilizando tecnicas de Machine Learning e Inteligencia Artificial. El modelo entrena con datos reales del dataset **CIC-DDoS2019** del Canadian Institute for Cybersecurity (UNB) y clasifica trafico de red en 7 categorias: trafico benigno y 6 tipos de ataque DDoS.

### Tipos de ataque clasificados

| Clase | Tipo | Descripcion |
|-------|------|-------------|
| BENIGN | Legitimo | Trafico normal de red |
| LDAP | Volumetrico | Amplificacion LDAP (UDP) |
| MSSQL | Protocolo | Amplificacion Microsoft SQL |
| NetBIOS | Volumetrico | Amplificacion NetBIOS |
| Portmap | Protocolo | Amplificacion RPC Portmap |
| Syn | Protocolo | SYN Flood (capa 4) |
| UDP | Volumetrico | UDP Flood |

---

## Modelos de Machine Learning

Se entrenaron y evaluaron **3 modelos de clasificacion multiclase**:

| Modelo | Accuracy | F1-Score | Precision | Recall |
|--------|----------|----------|-----------|--------|
| Random Forest (200 arboles) | 0.8907 | 0.8840 | 0.9065 | 0.8907 |
| **XGBoost (200 estimadores)** | **0.9281** | **0.9274** | **0.9329** | **0.9281** |
| MLP Red Neuronal (256-128-64) | 0.8590 | 0.8440 | 0.8743 | 0.8590 |

**Mejor modelo: XGBoost** con 92.81% de accuracy y 92.74% F1-Score.

### Visualizaciones generadas

| Archivo | Descripcion |
|---------|-------------|
| `resultados/matrices_confusion.png` | Matrices de confusion para los 3 modelos |
| `resultados/curvas_roc.png` | Curvas ROC (One-vs-Rest) por modelo |
| `resultados/comparacion_modelos.png` | Barras comparando Accuracy y F1 |
| `resultados/feature_importance.png` | Top 15 features mas importantes (RF y XGBoost) |
| `resultados/curva_loss_mlp.png` | Curva de perdida del MLP |
| `resultados/distribucion_clases.png` | Distribucion de muestras por clase |

---

## Dataset: CIC-DDoS2019

**Fuente:** Canadian Institute for Cybersecurity — University of New Brunswick  
**URL oficial:** https://www.unb.ca/cic/datasets/ddos-2019.html  
**Periodo:** Noviembre 2019  
**Trafico capturado:** 3 dias (13, 14, 22 de noviembre)

### Estructura del dataset

El dataset completo contiene **7 archivos CSV** organizados por tipo de ataque:

```
03-11/
  LDAP.csv      (831 MB)
  MSSQL.csv     (2.2 GB)
  NetBIOS.csv   (1.3 GB)
  Portmap.csv   (75 MB)
  Syn.csv       (1.7 GB)
  UDP.csv       (1.7 GB)
  UDPLag.csv    (305 MB)
```

**Total: ~8.2 GB** — Por esta razon, los CSVs NO se incluyen en el repositorio. El notebook realiza muestreo inteligente por chunks (15,000 muestras por clase) para procesar sin saturar la RAM.

---

## Requisitos

### Entorno

- Python 3.10+
- Minimo 4 GB de RAM disponible
- ~2 GB de espacio en disco (para la muestra procesada)
- Jupyter Notebook o JupyterLab

### Dependencias

```
numpy>=1.24
pandas>=2.0
scikit-learn>=1.3
xgboost>=2.0
matplotlib>=3.7
seaborn>=0.12
joblib>=1.3
```

---

## Instalacion y Ejecucion

### 1. Clonar el repositorio

```bash
git clone https://github.com/Chrisavt/examen-ia-ddos-utp.git
cd examen-ia-ddos-utp
```

### 2. Crear entorno virtual

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Instalar dependencias

```bash
pip install numpy pandas scikit-learn xgboost matplotlib seaborn joblib jupyter
```

### 4. Descargar el dataset

Descargar los archivos CSV de **CIC-DDoS2019** (7 archivos, ~8.2 GB total) desde:
https://www.unb.ca/cic/datasets/ddos-2019.html

Colocar los archivos en la carpeta `03-11/` dentro del repositorio:
```
examen-ia-ddos-utp/
  03-11/
    LDAP.csv
    MSSQL.csv
    NetBIOS.csv
    Portmap.csv
    Syn.csv
    UDP.csv
    UDPLag.csv
```

### 5. Ejecutar el notebook

```bash
jupyter notebook MLddos.ipynb
```

O abrir directamente en JupyterLab:
```bash
jupyter lab
```

### 6. Ejecutar todas las celdas

El notebook tiene **7 celdas** numeradas [1/6] a [6/6]:

1. **[1/6]** — Muestreo inteligente del dataset por chunks
2. **[2/6]** — Preprocesamiento: limpieza, codificacion, escalado, split 80/20
3. **[3/6]** — Entrenamiento de 3 modelos (RF, XGBoost, MLP)
4. **[4/6]** — Reportes de clasificacion detallados
5. **[5/6]** — 6 visualizaciones (matrices de confusion, ROC, etc.)
6. **[6/6]** — Resumen final, exportacion CSV y modelos serializados

**Tiempo estimado de ejecucion:** 5-15 minutos (dependiendo del hardware)

---

## Estructura del Repositorio

```
examen-ia-ddos-utp/
  MLddos.ipynb              # Notebook principal con toda la simulacion
  README.md                 # Este archivo
  .gitignore                # Archivos excluidos del repositorio
  requirements.txt          # Dependencias Python
  presentacion_ddos_utp.pptx # Presentacion PowerPoint (31 diapositivas)
  create_pptx.py            # Script para generar la presentacion
  demo_viva.py              # Demo en vivo: deteccion + bloqueo DDoS
  http_flood.py             # Generador de HTTP flood para demo
  syn_flood.py              # Generador de SYN flood para demo
  diagramas/                # Diagramas draw.io (6 diagramas)
    01_arquitectura_sistema.drawio
    02_pipeline_ml.drawio
    03_secuencia_deteccion.drawio
    04_topologia_red.drawio
    05_clases_ml.drawio
    06_flujo_datos_dfd.drawio
  resultados/               # Salidas generadas por el notebook
    matrices_confusion.png
    curvas_roc.png
    comparacion_modelos.png
    feature_importance.png
    curva_loss_mlp.png
    distribucion_clases.png
    resultados_modelos.csv
    reporte_clasificacion.txt
    modelo_rf.pkl           # Modelo Random Forest serializado
    scaler.pkl              # StandardScaler serializado
    label_encoder.pkl       # LabelEncoder serializado
    demo_log.json           # Log de la demostracion en vivo
  03-11/                    # [NO EN REPO] Dataset CIC-DDoS2019 (~8.2 GB)
  CSV-03-11.zip             # [NO EN REPO] Dataset comprimido (~877 MB)
```

---

## Metodologia

### Pipeline de Machine Learning

```
Dataset CIC-DDoS2019 (8.2 GB)
  -> Muestreo por chunks (15K muestras/clase, 7 clases = 105K filas)
  -> Limpieza (remover Inf, NaN, columnas irrelevantes)
  -> Codificacion de etiquetas (LabelEncoder)
  -> Escalado (StandardScaler)
  -> Split 80/20 estratificado
  -> Entrenamiento de 3 modelos
  -> Evaluacion (Accuracy, Precision, Recall, F1, ROC)
  -> Exportacion de resultados
```

### Algoritmos utilizados

- **Random Forest:** Ensemble de 200 arboles de decision, max_depth=30, class_weight='balanced'
- **XGBoost:** Gradient Boosting con 200 estimadores, learning_rate=0.1, subsample=0.8
- **MLP (Multi-Layer Perceptron):** Red neuronal con capas 256->128->64, ReLU, Adam, early stopping

### Justificacion de eleccion

- **Random Forest:** Robustez ante overfitting, interpretabilidad via feature importance
- **XGBoost:** Estado del arte en clasificacion tabular, manejo nativo de clases desbalanceadas
- **MLP:** Capacidad de capturar patrones no lineales complejos en el trafico de red

---

## Metricas de Evaluacion

| Metrica | Definicion | Importancia |
|---------|-----------|-------------|
| **Accuracy** | Proporcion total de predicciones correctas | Vision general del desempeno |
| **Precision** | De los predichos como ataque, cuantos lo son realmente | Minimizar falsos positivos |
| **Recall** | De los ataques reales, cuantos fueron detectados | Minimizar falsos negativos |
| **F1-Score** | Media armonica entre Precision y Recall | Balance entre ambos |
| **AUC-ROC** | Area bajo la curva ROC | Capacidad discriminativa global |

---

## Hallazgos Principales

1. **XGBoost supera a los demas modelos** con 92.8% de accuracy, demostrando la superioridad del gradient boosting en datos tabulares de trafico de red
2. **Syn y BENIGN** se detectan con precision casi perfecta (99-100%) en los 3 modelos
3. **NetBIOS y Portmap** son las clases mas dificiles de distinguir, probablemente por solapamiento de patrones con trafico benigno
4. **Las features mas relevantes** incluyen duracion del flujo, paquetes por segundo, y ratio de bytes forward/backward
5. **La red neuronal MLP** tiene el desempeno mas bajo (85.9%), sugiriendo que para datos tabulares los metodos de ensemble son superiores

---

## Referencias

1. Sharafaldin, I., Lashkari, A. H., Hakak, S., & Ghorbani, A. A. (2019). Developing realistic distributed denial of service (DDoS) attack dataset and taxonomy. *ACM International Conference Proceeding Series*, 70-75. https://doi.org/10.1145/3340997.3341005

2. Becerra-Suarez, F. L., Fernandez-Roman, I., & Forero, M. G. (2024). Improvement of distributed denial of service attack detection through machine learning and data processing. *Mathematics*, 12(9), 1294. https://doi.org/10.3390/math12091294

3. Najam, N. R. & Abduljawad, R. A. (2023). RF-RFE-SMOTE: A DoS and DDoS attack detection framework. *NTU Journal of Engineering and Technology*, 2(2), 29-47. https://doi.org/10.56286/ntujet.v2i2.436

4. Ma, R., Chen, X., & Zhai, R. (2023). A DDoS attack detection method based on natural selection of features and models. *Electronics*, 12(4), 1059. https://doi.org/10.3390/electronics12041059

5. Ali, T. E., Chong, Y.-W., & Manickam, S. (2023). Machine learning techniques to detect a DDoS attack in SDN: A systematic review. *Applied Sciences*, 13(5), 3183. https://doi.org/10.3390/app13053183

6. Mualfah, D., Ardiansyah, R., & Gunawan, R. (2025). Classification of DDoS attacks using the random forest method and class weight technique on the CICDDoS2019 dataset. *Jurnal CoSciTech*, 6(3), 530-535. https://doi.org/10.37859/coscitech.v6i3.10731

7. Mittal, M., Kumar, K., & Behal, S. (2022). Deep learning approaches for detecting DDoS attacks: A systematic review. *Soft Computing*. https://doi.org/10.1007/s00500-021-06608-1

8. Canadian Institute for Cybersecurity. (2019). CIC-DDoS2019 Dataset. *University of New Brunswick*. https://www.unb.ca/cic/datasets/ddos-2019.html

---

## Licencia

Este proyecto es parte del examen semestral de la asignatura IA Aplicada a la Ciberseguridad, Licenciatura en Ciberseguridad, Universidad Tecnologica de Panama (I Semestre 2026).

---

**Autor:** Christopher Abrego (Chrisavt)  
**Fecha:** Julio 2026
