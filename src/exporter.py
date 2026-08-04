"""
CSV exporter for the DLP pipeline.

Writes the scored and prioritized incident list to output/prioritized_incidents.csv.
Each row is self-contained: no cross-referencing with the source log is needed
to understand the incident.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path

from models import Incident

logger = logging.getLogger(__name__)

OUTPUT_FILE = Path("output/prioritized_incidents.csv")

FIELDNAMES = [
    "incident_id",
    "risk_score",
    "severity",
    "user_email",
    "resource_name",
    "service",
    "events_correlated",
    "timestamp",
    "reasons",
]


def export(incidents: list[Incident], output_path: Path = OUTPUT_FILE) -> Path:
    """Escribe la lista de incidentes priorizados en un archivo CSV.

    Crea el directorio destino si no existe, luego abre el archivo en modo escritura
    y vuelca todos los incidentes en orden (el scorer ya los entregó ordenados por
    risk_score descendente). Usa csv.DictWriter para garantizar el orden de las
    columnas y evitar inconsistencias si el dict de una fila tuviera claves extra.

    Parámetros:
        incidents: Lista de Incident ya scored y ordenada por risk_score descendente.
                   Se espera que vengan del scorer; si llegan sin score, se escribirá 0.
        output_path: Ruta del archivo CSV de salida. Por defecto "output/prioritized_incidents.csv".
                     El directorio padre se crea automáticamente si no existe.

    Retorna:
        Path absoluto del archivo CSV generado, útil para loguearlo en main().
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()

        for incident in incidents:
            writer.writerow(_to_row(incident))

    logger.info("Exported %d incidents to %s", len(incidents), output_path.resolve())
    return output_path.resolve()


# Internal helpers
def _to_row(incident: Incident) -> dict[str, str]:
    """Convierte un Incident en un diccionario plano con valores seguros para CSV.

    Todos los valores se convierten a string. Los campos numéricos (risk_score,
    events_correlated) se convierten explícitamente con str() para evitar que
    DictWriter los serialice de forma inesperada. La lista de reasons se une
    con " | " como separador para que quepan en una sola celda y sigan siendo
    legibles sin necesidad de abrir el log original.

    Parámetros:
        incident: Incident con todos sus campos ya calculados (risk_score, severity, reasons).

    Retorna:
        Diccionario con exactamente las claves definidas en FIELDNAMES, todas como strings.
    """
    return {
        "incident_id":      incident.incident_id,
        "risk_score":       str(incident.risk_score),
        "severity":         incident.severity,
        "user_email":       incident.user_email,
        "resource_name":    incident.resource_name,
        "service":          incident.service,
        "events_correlated": str(incident.event_count),
        "timestamp":        incident.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "reasons":          " | ".join(incident.reasons),
    }
