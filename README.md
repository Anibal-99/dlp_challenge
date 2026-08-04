# DLP Audit Log Analyzer

Script de Python de calidad productiva que lee audit logs de seguridad de Google Cloud / Google Workspace, correlaciona eventos en incidentes, calcula un score de riesgo explicable para cada incidente y exporta un reporte priorizado.

Implementa el RFC de Data Loss Prevention para Colibrí, una fintech que opera sobre Google Workspace y GCP.

**RFC:** [R.F.C — Data Loss Prevention (Google Docs)](https://docs.google.com/document/d/1c8lxG3ljbUn2aL6Cp-s24CK7QlsfLAxCBssqafkyNKQ/edit?usp=sharing)

---

## Estructura del proyecto

```
dlp_challenge/
├── README.md
├── requirements.txt
│
├── data/
│   ├── mock_logs_json_cloud_audit.json
│   └── mock_logs_csv_cloud_audit.csv
│
├── src/
│   ├── models.py                   — Dataclasses AuditEvent e Incident (contratos de datos)
│   ├── parser.py                   — Ingesta y normalización de JSON/CSV
│   ├── sensitive_data_detector.py  — Detección local de datos sensibles (PII, PCI, credenciales)
│   ├── correlator.py               — Agrupación de eventos en incidentes
│   ├── scorer.py                   — Motor de scoring determinístico multi-señal
│   ├── exporter.py                 — Generación del reporte CSV
│   └── main.py                     — Orquestación del pipeline y CLI
│
└── output/
    └── prioritized_incidents.csv   (generado al ejecutar)
```

---

## Requisitos

- Python 3.10 o superior
- Sin dependencias externas — solo biblioteca estándar de Python

---

## Instalación

```bash
git clone <repository-url>
cd dlp_challenge
```

No se requiere `pip install`.

---

## Uso

```bash
# Input JSON
python src/main.py data/mock_logs_json_cloud_audit.json

# Input CSV
python src/main.py data/mock_logs_csv_cloud_audit.csv

# Output personalizado
python src/main.py data/mock_logs_json_cloud_audit.json --output reports/incidents.csv

# Logging detallado (nivel DEBUG)
python src/main.py data/mock_logs_json_cloud_audit.json --verbose
```

El reporte se escribe en `output/prioritized_incidents.csv` por defecto.

---

## Etapas del pipeline

```
Archivo de entrada (.json o .csv)
        │
        ▼
   parser.py  ──►  list[AuditEvent]    (normalizado, independiente del formato)
        │
        ▼
correlator.py  ──►  list[Incident]     (eventos agrupados por patrón)
        │
        ▼
   scorer.py  ──►  list[Incident]      (con score, severidad y razones)
        │
        ▼
  exporter.py  ──►  output/prioritized_incidents.csv
```

---

## Cómo funciona la correlación

Los eventos se agrupan en incidentes usando dos reglas. Cada evento pertenece a exactamente un incidente.

### Regla 1 — Campaña geográfica (ventana de 48 horas)

Eventos que apuntan al **mismo recurso desde el mismo país** dentro de 48 horas se agrupan en un incidente.

Este patrón detecta ataques regionales coordinados o ubicaciones geográficas comprometidas que acceden repetidamente al mismo recurso (ej: 15 eventos desde China sobre `resource2` en una ventana de 48 horas).

### Regla 2 — Campaña de destino (ventana de 48 horas)

Eventos que comparten el **mismo destino externo** con `sharing_scope` público o externo dentro de 48 horas se agrupan en un incidente.

Este patrón detecta exfiltración repetida al mismo endpoint externo desde múltiples fuentes (ej: múltiples usuarios enviando datos a `External Email` con scope público en una ventana corta).

### Fallback

Todo evento que no califica para ninguna regla se convierte en un incidente individual.

### Configuración

Las ventanas temporales son constantes nombradas en `src/correlator.py`:

```python
GEOGRAPHIC_WINDOW_HOURS: int = 48
DESTINATION_WINDOW_HOURS: int = 48
```

---

## Cómo funciona el score de riesgo

Cada incidente recibe un score entre 0 y 100. El score se construye de forma incremental evaluando nueve señales independientes. Cada señal que aplica suma puntos y agrega una razón legible al incidente.

| # | Señal | Pts máx | Qué captura |
|---|---|---|---|
| 1 | Contiene datos sensibles | 20 | Dato clasificado como Restringido en el RFC |
| 2 | Sharing scope (público / externo / interno) | 25 / 15 / 5 | Radio de exposición |
| 3 | Registros afectados (>1k / >100 / >10) | 25 / 10 / 5 | Volumen de datos |
| 4 | Actividad sospechosa | 15 | Señal del clasificador de comportamiento |
| 5 | Acción sospechosa exitosa | 10 | Exfiltración confirmada vs intento fallido |
| 6 | Riesgo del servicio (BigQuery / IAM / Storage) | 10 / 10 / 5 | Perfil de riesgo de la plataforma |
| 7 | Acción peligrosa (make_public / export / download) | 15 / 10 / 8 | Severidad de la acción ejecutada |
| 8 | Autenticación débil (solo password) | 5 | Sin MFA ni SSO |
| 9 | Profundidad de correlación (5+ / 3+ / 2 eventos) | 15 / 10 / 5 | Indicador de campaña |

El score final se capea en 100.

### Umbrales de severidad

| Severidad | Score |
|---|---|
| Critical | ≥ 75 |
| High | ≥ 50 |
| Medium | ≥ 25 |
| Low | < 25 |

Los umbrales se definen en `src/scorer.py`:

```python
SEVERITY_THRESHOLDS: dict[str, int] = {
    "Critical": 75,
    "High":     50,
    "Medium":   25,
    "Low":       0,
}
```

### Ejemplo de fila en el reporte

```
incident_id  risk_score  severity  user_email        resource_name  service   events_correlated  reasons
INC-00001    100         Critical  user@example.com  resource2      BigQuery  7                  +20 Contains PII | +25 Data exposed publicly | ...
```

---

## Formato de salida

`output/prioritized_incidents.csv` — una fila por incidente, ordenado por `risk_score` descendente.

| Columna | Descripción |
|---|---|
| `incident_id` | Identificador determinístico (INC-00001, …) |
| `risk_score` | 0–100 |
| `severity` | Low / Medium / High / Critical |
| `user_email` | Usuario del evento primario (más temprano) |
| `resource_name` | Recurso del evento primario |
| `service` | Servicio de GCP/Workspace del evento primario |
| `events_correlated` | Cantidad de eventos agrupados en el incidente |
| `timestamp` | Timestamp del evento primario (ISO 8601) |
| `reasons` | Razones del score separadas por pipe |

---

## Supuestos

- Ambos archivos de input contienen las mismas columnas. El parser valida los campos obligatorios y descarta registros malformados con un warning.
- Los valores de `event_id` son únicos dentro de cada archivo. Se usan para rastrear qué eventos fueron asignados a un incidente durante la correlación.
- Los dos datasets provistos (JSON y CSV) son estructuralmente idénticos pero generados de forma independiente — contienen registros distintos. Esto es consistente con datos sintéticos de un challenge.
- Los timestamps se asumen en UTC (formato: `YYYY-MM-DDTHH:MM:SSZ`).
- El modelo de scoring es intencionalmente conservador a nivel de evento individual. Los scores suben de forma pronunciada cuando múltiples señales se disparan juntas — esto es por diseño, siguiendo el objetivo del RFC de reducir falsos positivos exigiendo múltiples señales antes de clasificar un incidente como de alta severidad.

---

## Posibles mejoras futuras

| Área | Mejora |
|---|---|
| Correlación | Agregar regla de comportamiento por usuario cuando el dataset contenga usuarios repetidos |
| Correlación | Soporte para reglas configurables via archivo YAML/JSON |
| Scoring | Cargar pesos de señales desde configuración externa para ajustar sin modificar código |
| Output | Agregar formatos JSON y compatibles con SIEM (CEF/LEEF) |
| Output | Generar un reporte HTML resumido con distribución de incidentes por severidad |
| Observabilidad | Emitir logs estructurados en JSON para ingestión en Cloud Logging |
| Testing | Agregar tests unitarios para coerciones del parser, señales del scorer y reglas del correlator |
| Escala | Procesar archivos grandes en streaming en lugar de cargar todo en memoria (para logs > 1 GB) |
