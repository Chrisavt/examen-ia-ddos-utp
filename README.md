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
  resultados/               # Salidas generadas por el notebook
    matrices_confusion.png
    curvas_roc.png
    comparacion_modelos.png
    feature_importance.png
    curva_loss_mlp.png
    distribucion_clases.png
    resultados_modelos.csv
    reporte_clasificacion.txt
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

1. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. *4th International Conference on Information Systems Security and Privacy (ICISSP)*, 108-116.

2. Tavallaee, M., Bagheri, E., Lu, W., & Ghorbani, A. A. (2009). A Detailed Analysis of the KDD CUP 99 Data Set. *IEEE Symposium on Computational Intelligence for Security and Defense Applications (CISDA)*.

3. Chen, T., & Guestrin, C. (2016). XGBoost: A Scalable Tree Boosting System. *Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining*, 785-794.

4. Breiman, L. (2001). Random Forests. *Machine Learning*, 45(1), 5-32.

5. Canadian Institute for Cybersecurity. (2019). CIC-DDoS2019 Dataset. *University of New Brunswick*. https://www.unb.ca/cic/datasets/ddos-2019.html

6. NETSCOUT Arbor. (2024). *19th Annual Worldwide Infrastructure Security Report*.

7. MITRE Corporation. (2024). MITRE ATT&CK — Denial of Service. https://attack.mitre.org/techniques/T1499/

---

## Licencia

Este proyecto es parte del examen semestral de la asignatura IA Aplicada a la Ciberseguridad, Licenciatura en Ciberseguridad, Universidad Tecnologica de Panama (I Semestre 2026).

---

**Autor:** Christopher Abrego (Chrisavt)  
**Fecha:** Julio 2026
