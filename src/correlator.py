from __future__ import annotations

import logging
from datetime import timedelta
from itertools import count
from typing import Iterator

from models import AuditEvent, Incident

logger = logging.getLogger(__name__)

# Configuration — adjust these without touching any logic

GEOGRAPHIC_WINDOW_HOURS: int = 48
DESTINATION_WINDOW_HOURS: int = 48
EXTERNAL_SCOPES: frozenset[str] = frozenset({"public", "external"})


def correlate(events: list[AuditEvent]) -> list[Incident]:
    """Agrupa AuditEvents en Incidents aplicando las reglas de correlación configuradas.

    Ejecuta las reglas en orden de prioridad. Una vez que un evento es asignado
    a un incidente por la primera regla, no puede ser reasignado por las siguientes.
    Los eventos que no califican para ninguna regla se convierten en incidentes
    de un solo evento (fallback), garantizando que todo evento del input termine
    en exactamente un incidente.

    Orden de evaluación:
        1. Regla geográfica: mismo recurso + mismo país dentro de GEOGRAPHIC_WINDOW_HOURS.
        2. Regla de destino: mismo destino externo dentro de DESTINATION_WINDOW_HOURS.
        3. Fallback: evento individual → incidente propio.

    Parámetros:
        events: Lista de AuditEvent normalizados, ordenados por timestamp ascendente.
                El orden es requisito de las funciones internas de ventana temporal.

    Retorna:
        Lista de Incident. Cada AuditEvent del input aparece en exactamente un Incident.
        Los incidentes multi-evento aparecen primero (por orden de creación), seguidos
        de los incidentes individuales del fallback.
    """
    id_gen = _incident_id_generator()
    assigned: set[int] = set()
    incidents: list[Incident] = []

    # Rule 1: mismo recurso + mismo pais dentro de GEOGRAPHIC_WINDOW_HOURS
    for group in _group_by_geography(events):
        if len(group) > 1:
            incident = Incident(incident_id=next(id_gen), events=group)
            incidents.append(incident)
            assigned.update(e.event_id for e in group)
            logger.debug(
                "Geographic correlation: %d events → %s (resource=%s, country=%s)",
                len(group),
                incident.incident_id,
                group[0].resource_name,
                group[0].country,
            )

    # Rule 2: mismo destino + external/public scope dentro de DESTINATION_WINDOW_HOURS
    # Solo toma los enventos que no fueron tomados en la regla 1.
    remaining = [e for e in events if e.event_id not in assigned]
    for group in _group_by_destination(remaining):
        if len(group) > 1:
            incident = Incident(incident_id=next(id_gen), events=group)
            incidents.append(incident)
            assigned.update(e.event_id for e in group)
            logger.debug(
                "Destination correlation: %d events → %s (destination=%s, scope=%s)",
                len(group),
                incident.incident_id,
                group[0].destination,
                group[0].sharing_scope,
            )

    # Eventos que no fueron asignados por ninguna regla
    for event in events:
        if event.event_id not in assigned:
            incidents.append(Incident(incident_id=next(id_gen), events=[event]))

    correlated_count = sum(i.event_count for i in incidents if i.event_count > 1)
    logger.info(
        "Correlation complete: %d events → %d incidents (%d events in multi-event incidents)",
        len(events),
        len(incidents),
        correlated_count,
    )
    return incidents


# Correlation rules
def _group_by_geography(events: list[AuditEvent]) -> Iterator[list[AuditEvent]]:
    """Genera grupos de eventos con el mismo recurso y país dentro de la ventana temporal.

    Implementa un algoritmo de ventana deslizante sobre los eventos ordenados por
    timestamp. Mantiene un bucket por cada combinación (resource_name, country).
    Cuando un nuevo evento entra dentro de la ventana desde el primer evento del
    bucket, se agrega al grupo. Cuando cae fuera de la ventana, el bucket actual
    se emite como grupo completo y se inicia uno nuevo con el evento actual.

    Este patrón detecta campañas regionales coordinadas: múltiples usuarios desde
    el mismo país atacando el mismo recurso en un período corto de tiempo.

    Ej:
    Clientes + Argentina
        Evento 1
        Evento 2
        Evento 3
    """

    # Objetivo: agrupar los eventos que ocurrieron en el mismo país, sobre el mismo recurso y dentro de un período de tiempo determinado
    # Si dos eventos ocurrieron con menos de 48 horas de diferencia, pueden pertenecer al mismo grupo

    window = timedelta(hours=GEOGRAPHIC_WINDOW_HOURS)
    buckets: dict[tuple[str, str], list[AuditEvent]] = {} #tomar el resource_name y country, como clave para cada evento

    for event in events:
        key = (event.resource_name, event.country)
        if key not in buckets:
            buckets[key] = [event]
            continue

        existing = buckets[key]
        if event.timestamp - existing[0].timestamp <= window:
            existing.append(event)
        else:
            yield existing
            buckets[key] = [event]

    yield from buckets.values()


def _group_by_destination(events: list[AuditEvent]) -> Iterator[list[AuditEvent]]:
    """Genera grupos de eventos con el mismo destino externo dentro de la ventana temporal.

    Aplica el mismo algoritmo de ventana deslizante que _group_by_geography, pero
    agrupa por combinación (destination, sharing_scope). Solo procesa eventos cuyo
    sharing_scope esté dentro de EXTERNAL_SCOPES (public o external), ignorando
    eventos con scope interno o privado ya que no representan exfiltración.

    Este patrón detecta campañas de exfiltración repetida: múltiples fuentes enviando
    datos hacia el mismo endpoint externo (ej. External Email, Google Sheets público)
    en una ventana de tiempo corta.

    Parámetros:
        events: Lista de AuditEvent ordenados por timestamp ascendente. Debe contener
                únicamente los eventos no asignados por reglas anteriores.

    Yields:
        Lista de AuditEvent que comparten (destination, sharing_scope) con scope
        externo/público y cuyo span temporal es menor o igual a DESTINATION_WINDOW_HOURS.
        Incluye grupos de un solo evento (el llamador filtra los grupos con len > 1).
    """
    window = timedelta(hours=DESTINATION_WINDOW_HOURS)
    buckets: dict[tuple[str, str], list[AuditEvent]] = {}

    for event in events:
        if event.sharing_scope not in EXTERNAL_SCOPES:
            continue

        key = (event.destination, event.sharing_scope)
        if key not in buckets:
            buckets[key] = [event]
            continue

        existing = buckets[key]
        if event.timestamp - existing[0].timestamp <= window:
            existing.append(event)
        else:
            yield existing
            buckets[key] = [event]

    yield from buckets.values()


def _incident_id_generator() -> Iterator[str]:
    """Genera identificadores únicos de incidente en formato INC-NNNNN de forma infinita.

    Usa itertools.count para contar enteros desde 1 sin límite superior.
    El llamador consume un valor por vez con next(), por lo que el generador
    solo avanza cuando se le pide el siguiente ID. El formato con cero-padding
    de 5 dígitos garantiza orden lexicográfico correcto hasta INC-99999.

    Yields:
        Strings con formato "INC-00001", "INC-00002", ..., "INC-99999", "INC-100000", etc.
    """
    for n in count(1):
        yield f"INC-{n:05d}"
