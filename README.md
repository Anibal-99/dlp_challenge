# DLP
Un script de Python con calidad de producción que lee registros de auditoría de seguridad de Google Cloud y Google Workspace, correlaciona eventos relacionados en incidentes, calcula una puntuación de riesgo explicable para cada incidente y exporta un informe priorizado.

Desarrollado como una implementación del RFC: Data Loss Prevention para Colibrí, una fintech que opera sobre Google Workspace y GCP.

**RFC:** [R.F.C — Data Loss Prevention (Google Docs)](https://docs.google.com/document/d/1c8lxG3ljbUn2aL6Cp-s24CK7QlsfLAxCBssqafkyNKQ/edit?usp=sharing)

---

## Project Structure

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
│   ├── models.py       — AuditEvent and Incident dataclasses (data contracts)
│   ├── parser.py       — JSON/CSV ingestion and normalization
│   ├── correlator.py   — Event grouping into incidents
│   ├── scorer.py       — Deterministic multi-signal risk scoring
│   ├── exporter.py     — CSV report generation
│   └── main.py         — Pipeline orchestration and CLI entry point
│
└── output/
    └── prioritized_incidents.csv   (generated on run)
```

---

## Requirements

- Python 3.10 or later
- No third-party dependencies — standard library only

---

## Installation

```bash
git clone <repository-url>
cd dlp_challenge
```

No `pip install` step required.

---

## Usage

```bash
# JSON input
python src/main.py data/mock_logs_json_cloud_audit.json

# CSV input
python src/main.py data/mock_logs_csv_cloud_audit.csv

# Custom output path
python src/main.py data/mock_logs_json_cloud_audit.json --output reports/incidents.csv

# Verbose (debug-level) logging
python src/main.py data/mock_logs_json_cloud_audit.json --verbose
```

The report is written to `output/prioritized_incidents.csv` by default.

---

## Pipeline Stages

```
Input file (.json or .csv)
        │
        ▼
   parser.py  ──►  list[AuditEvent]        (normalized, format-agnostic)
        │
        ▼
correlator.py  ──►  list[Incident]          (events grouped by pattern)
        │
        ▼
   scorer.py  ──►  list[Incident]           (scored, sorted, severity assigned)
        │
        ▼
  exporter.py  ──►  output/prioritized_incidents.csv
```

---

## Cómo Funciona la Correlación

Los eventos se agrupan en incidentes utilizando dos reglas. Cada evento pertenece exactamente a un único incidente.
### Campaña geográfica (ventana de 48 horas)

Los eventos dirigidos al mismo recurso desde el mismo país dentro de una ventana de 48 horas se agrupan en un mismo incidente.

Este patrón permite detectar ataques regionales coordinados o ubicaciones geográficas comprometidas que acceden repetidamente a un recurso sensible (por ejemplo, 15 eventos provenientes de China dirigidos a resource2 en un período de 48 horas).

### Rule 2 — Campaña por destino (ventana de 48 horas)

Los eventos que comparten el mismo destino externo con un alcance de compartición public o external dentro de una ventana de 48 horas se agrupan en un mismo incidente.

Este patrón detecta intentos repetidos de exfiltración de datos hacia un mismo destino externo desde múltiples orígenes (por ejemplo, varios usuarios enviando información a External Email con alcance público en un corto período de tiempo).

### Caso por defecto

Cualquier evento que no coincida con ninguna de las reglas anteriores se convierte en un incidente individual.
### Configuración

Las ventanas de tiempo se definen como constantes al inicio de `src/correlator.py`:

```python
GEOGRAPHIC_WINDOW_HOURS: int = 48
DESTINATION_WINDOW_HOURS: int = 48
```

---

## Cómo Funciona el Puntaje de Riesgo

Cada incidente recibe un puntaje entre 0 y 100. Este puntaje se construye de forma incremental evaluando nueve señales independientes. Cada señal que se activa suma puntos y agrega una explicación legible a la lista de razones del incidente.

| # | Signal | Max pts | What it captures |
|---|---|---|---|
| 1 | Contains PII | 20 | Data classified as Restricted per the RFC |
| 2 | Sharing scope (public / external / internal) | 25 / 15 / 5 | Exposure radius |
| 3 | Records affected (>1k / >100 / >10) | 25 / 10 / 5 | Data volume |
| 4 | Suspicious activity flag | 15 | Behavioral classifier signal |
| 5 | Successful suspicious action | 10 | Confirmed exfiltration vs failed attempt |
| 6 | Service risk (BigQuery / IAM / Storage) | 10 / 10 / 5 | Platform-level risk profile |
| 7 | Dangerous action (make_public / export / download) | 15 / 10 / 8 | Action severity |
| 8 | Weak authentication (password only) | 5 | No MFA or SSO |
| 9 | Correlation depth (5+ / 3+ / 2 events) | 15 / 10 / 5 | Campaign indicator |

El puntaje final está limitado a un máximo de 100.
### Umbrales de severidad

| Severity | Score |
|---|---|
| Critical | ≥ 75 |
| High | ≥ 50 |
| Medium | ≥ 25 |
| Low | < 25 |

Los umbrales se definen mediante un único diccionario en `src/scorer.py`:

```python
SEVERITY_THRESHOLDS: dict[str, int] = {
    "Critical": 75,
    "High":     50,
    "Medium":   25,
    "Low":       0,
}
```

### Ejemplo de una fila del reporte

```
incident_id  risk_score  severity  user_email              resource_name  service      events_correlated  reasons
INC-00001    100         Critical  user@example.com        resource2      BigQuery     7                  +20 Contains PII | +25 Data exposed publicly | +25 Large volume... | ...
```

---

## Formato de Salida

`output/prioritized_incidents.csv` — una fila por incidente, ordenados de forma descendente según `risk_score`.

| Column | Description |
|---|---|
| `incident_id` | Deterministic identifier (INC-00001, …) |
| `risk_score` | 0–100 |
| `severity` | Low / Medium / High / Critical |
| `user_email` | User from the primary (earliest) event |
| `resource_name` | Resource from the primary event |
| `service` | GCP/Workspace service from the primary event |
| `events_correlated` | Number of events grouped into this incident |
| `timestamp` | Timestamp of the primary event (ISO 8601) |
| `reasons` | Pipe-separated list of scoring reasons |

---

## Supuestos
- Ambos archivos de entrada contienen las mismas columnas. El parser valida los campos obligatorios y omite los registros malformados mostrando una advertencia.
- Los valores de event_id son únicos dentro de cada archivo. Se utilizan para controlar qué eventos ya fueron asignados a un incidente durante el proceso de correlación.
- Los dos conjuntos de datos proporcionados (JSON y CSV) son estructuralmente idénticos, pero fueron generados de manera independiente; por lo tanto, contienen registros distintos. Esto es consistente con un conjunto de datos sintético para el challenge.
- Se asume que todas las marcas de tiempo están en UTC (formato: YYYY-MM-DDTHH:MM:SSZ).
- El modelo de puntuación es intencionalmente conservador para incidentes de un solo evento. El puntaje aumenta considerablemente cuando múltiples señales se activan simultáneamente, ya que el objetivo del RFC es reducir los falsos positivos exigiendo varias evidencias antes de clasificar un incidente con alta severidad.
