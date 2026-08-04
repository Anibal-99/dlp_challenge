from __future__ import annotations

import csv
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from models import AuditEvent
from sensitive_data_detector import detect_pii

logger = logging.getLogger(__name__)

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def load_events(file_path: str | Path) -> list[AuditEvent]:
    """Lee un archivo de audit logs en formato JSON o CSV y devuelve eventos normalizados.

    Detecta el formato automáticamente por la extensión del archivo (.json o .csv).
    Delega la lectura al reader correspondiente y normaliza cada registro en plano
    a un objeto AuditEvent. Los registros malformados se descartan con un
    warning en lugar de interrumpir el proceso. La lista resultante se ordena por
    timestamp ascendente, requisito del correlator.

    Parámetros:
        file_path: Ruta al archivo de audit logs. Puede ser str o Path.

    Retorna:
        Lista de AuditEvent válidos, ordenados por timestamp de menor a mayor.

    Lanza:
        FileNotFoundError: Si el archivo no existe en la ruta indicada.
        ValueError: Si la extensión del archivo no es .json ni .csv.
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Audit log not found: {path}")

    extension = path.suffix.lower()

    if extension == ".json":
        raw_records = _read_json(path)
    elif extension == ".csv":
        raw_records = _read_csv(path)
    else:
        raise ValueError(
            f"Unsupported file format '{extension}'. Expected .json or .csv."
        )

    logger.info("Loaded %d raw records from %s", len(raw_records), path.name)

    events = []
    skipped = 0

    for i, record in enumerate(raw_records):
        try:
            events.append(_normalize(record))
        except (KeyError, ValueError) as exc:
            logger.warning("Skipping record %d — %s", i, exc)
            skipped += 1

    if skipped:
        logger.warning("Skipped %d malformed records", skipped)

    events.sort(key=lambda e: e.timestamp)

    enriched = _enrich_pii(events)
    if enriched:
        logger.info(
            "PII enrichment: %d eventos reclasificados por el detector local", enriched
        )

    logger.info("Parsed %d valid events", len(events))
    return events


# PII enrichment
# TODO: Revisar como puedo enriquecer los eventos que no se clasifican (segun el dataset)
def _enrich_pii(events: list[AuditEvent]) -> int:
    """Ejecuta el detector local de PII sobre eventos que el upstream no clasificó.

    Recorre todos los AuditEvent cuyo campo contains_pii sea False y corre
    detect_pii() sobre el texto de event_description. Si el detector encuentra
    PII con confianza suficiente (según MIN_CONFIDENCE en sensitive_data_detector.py),
    actualiza el evento en lugar:
      - Establece contains_pii = True
      - Fusiona los tipos detectados con los que ya tenía en pii_types

    Esta función no modifica los eventos que ya tienen contains_pii = True,
    respetando la clasificación del upstream (Google Cloud DLP tiene mayor
    precisión para datos estructurados y a escala).

    Parámetros:
        events: Lista de AuditEvent ya normalizados y ordenados.

    Retorna:
        Cantidad de eventos que fueron reclasificados (contains_pii pasó de False a True).
    """
    enriched_count = 0
    for event in events:
        if event.contains_pii:
            continue

        result = detect_pii(event.event_description)
        if not result.detected:
            continue

        event.contains_pii = True
        existing = {t.strip() for t in event.pii_types.split(",") if t.strip()}
        merged = existing | set(result.pii_types)
        event.pii_types = ", ".join(sorted(merged))
        enriched_count += 1
        logger.debug(
            "PII detectada localmente en evento %d: tipos=%s confianza=%.2f",
            event.event_id,
            event.pii_types,
            result.confidence,
        )

    return enriched_count

# Internal readers
def _read_json(path: Path) -> list[dict[str, Any]]:
    """Lee un archivo JSON y devuelve su contenido como lista de diccionarios.

    Valida que el elemento raíz del JSON sea un array. Si el archivo contiene
    un objeto en la raíz en lugar de un array, lanza un ValueError con mensaje
    claro en lugar de fallar silenciosamente más adelante.

    Parámetros:
        path: Ruta al archivo .json a leer.

    Retorna:
        Lista de diccionarios, uno por cada registro del log.

    Lanza:
        ValueError: Si el JSON no contiene un array en la raíz.
    """
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError("JSON file must contain a top-level array of records.")
    return data


def _read_csv(path: Path) -> list[dict[str, Any]]:
    """Lee un archivo CSV y devuelve su contenido como lista de diccionarios.

    Utiliza csv.DictReader, que interpreta la primera fila como header y
    mapea cada columna a su nombre correspondiente en cada registro.
    El resultado tiene la misma forma que los dicts del JSON, permitiendo
    que _normalize() procese ambos formatos sin distinción.

    Parámetros:
        path: Ruta al archivo .csv a leer.

    Retorna:
        Lista de diccionarios, uno por cada fila del CSV (excluido el header).
    """
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _normalize(record: dict[str, Any]) -> AuditEvent:
    """Convierte un diccionario plano (de JSON o CSV) en un objeto de AuditEvent.

    Aplica todas las coerciones de tipo necesarias para unificar las diferencias
    entre formatos: los booleanos llegan como bool en JSON y como strings "true"/"false"
    en CSV; los timestamps llegan como strings en ambos casos. También normaliza
    a minúsculas los campos usados en comparaciones (user_email, sharing_scope,
    user_role) para evitar fallos.

    Parámetros:
        record: Diccionario crudo con los campos del log tal como vienen del archivo.

    Retorna:
        AuditEvent con todos los campos correctos y normalizados.

    Lanza:
        KeyError: Si falta un campo obligatorio en el registro.
        ValueError: Si un campo numérico no puede convertirse a int.
    """
    return AuditEvent(
        event_id=int(record["event_id"]),
        timestamp=_parse_timestamp(record["timestamp"]),
        service=_str(record, "service"),
        user_email=_str(record, "user_email").lower(),
        action=_str(record, "action"),
        resource_name=_str(record, "resource_name"),
        resource_type=_str(record, "resource_type"),
        contains_pii=_bool(record["contains_pii"]),
        pii_types=_str(record, "pii_types"),
        records_affected=int(record.get("records_affected", 0) or 0),
        destination=_str(record, "destination"),
        sharing_scope=_str(record, "sharing_scope").lower(),
        success=_bool(record["success"]),
        ip_address=_str(record, "ip_address"),
        country=_str(record, "country"),
        severity=_str(record, "severity"),
        event_type=_str(record, "event_type"),
        file_size=int(record.get("file_size", 0) or 0),
        download_time=int(record.get("download_time", 0) or 0),
        user_role=_str(record, "user_role").lower(),
        source_device=_str(record, "source_device"),
        authentication_method=_str(record, "authentication_method"),
        data_center_location=_str(record, "data_center_location"),
        event_description=_str(record, "event_description"),
        event_category=_str(record, "event_category"),
        event_source=_str(record, "event_source"),
    )


def _parse_timestamp(value: Any) -> datetime:
    """Parsea un valor de timestamp a un objeto datetime con timezone UTC.

    Soporta dos casos: si el valor ya es un datetime, le agrega timezone UTC. Si es un string,
    lo parsea con el formato ISO 8601 definido en TIMESTAMP_FORMAT y le agrega UTC.

    Parámetros:
        value: String con formato "YYYY-MM-DDTHH:MM:SSZ" u objeto datetime.

    Retorna:
        Objeto datetime con timezone UTC explícita.

    Lanza:
        ValueError: Si el string no coincide con el formato esperado.
    """
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc)
    return datetime.strptime(str(value).strip(), TIMESTAMP_FORMAT).replace(
        tzinfo=timezone.utc
    )


def _bool(value: Any) -> bool:
    """Normaliza un valor booleano que puede venir como bool nativo o como string.

    Resuelve la diferencia central entre los dos formatos de entrada: en JSON
    los campos booleanos llegan como True/False de Python, mientras que en CSV
    llegan como las strings "true" o "false". Esta función unifica ambos casos
    y siempre devuelve un bool de Python.

    Parámetros:
        value: Bool nativo de Python o string con valor "true"/"false" (case-insensitive).

    Retorna:
        True si el valor es True o la string "true" (ignorando mayúsculas).
        False en cualquier otro caso.
    """
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


def _str(record: dict[str, Any], key: str) -> str:
    """Extrae un campo del diccionario como string limpio, tolerando ausencias y None.

    Si la clave no existe en el diccionario, devuelve string vacío en lugar de
    lanzar KeyError. Si el valor existe pero es None o vacío, también devuelve
    string vacío. Si el valor existe, aplica strip() para eliminar espacios.

    Parámetros:
        record: Diccionario con los campos del registro crudo.
        key: Nombre del campo a extraer.

    Retorna:
        String con el valor del campo sin espacios al inicio/final, o "" si
        el campo no existe o es None.
    """
    return str(record.get(key, "") or "").strip()
