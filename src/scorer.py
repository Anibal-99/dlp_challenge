"""
Risk scoring engine for the DLP pipeline.

Assigns a deterministic, explainable risk score (0–100) to each Incident
by accumulating weighted signals drawn from the RFC classification model.

Signal groups (in evaluation order):
  1. Data sensitivity    — PII presence and type
  2. Exposure radius     — sharing scope
  3. Data volume         — records affected
  4. Behavioral signal   — event type (suspicious vs normal)
  5. Successful action   — confirmed exfiltration vs failed attempt
  6. Service risk        — platform-level risk profile
  7. Action severity     — what was actually done
  8. Authentication      — strength of identity verification
  9. Campaign indicator  — number of correlated events

Each signal adds points and appends a reason string.
The final score is capped at MAX_SCORE.
Severity thresholds are named constants — change them without touching logic.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from models import AuditEvent, Incident

logger = logging.getLogger(__name__)

# Thresholds — modify here only

MAX_SCORE: int = 100

SEVERITY_THRESHOLDS: dict[str, int] = {
    "Critical": 75,
    "High":     50,
    "Medium":   25,
    "Low":       0,
}

# Actions that are inherently high-risk regardless of other signals
HIGH_RISK_ACTIONS: frozenset[str] = frozenset(
    {"make_public", "export", "policy_change", "download", "share", "delete"}
)

# Services with elevated risk profiles per the RFC
HIGH_RISK_SERVICES: frozenset[str] = frozenset({"bigquery", "iam"})
MEDIUM_RISK_SERVICES: frozenset[str] = frozenset({"cloud storage"})


def score_incidents(incidents: list[Incident]) -> list[Incident]:
    """Calcula y asigna el score de riesgo a todos los incidentes de la lista.

    Itera sobre cada Incident, delega el cálculo a _score() y escribe los
    resultados directamente en el objeto (risk_score, severity, reasons).
    Al finalizar, ordena la lista por risk_score descendente para que el
    exporter escriba los incidentes más críticos primero en el reporte.

    Parámetros:
        incidents: Lista de Incident generados por el correlator, sin scores asignados.
                   Cada Incident contiene uno o más AuditEvents correlacionados.

    Retorna:
        La misma lista de Incident (mutada en lugar), ahora con risk_score, severity
        y reasons completos, ordenada de mayor a menor risk_score.
    """
    for incident in incidents:
        score, reasons = _score(incident)
        incident.risk_score = score
        incident.severity = _to_severity(score)
        incident.reasons = reasons
        logger.debug(
            "%s  score=%d  severity=%s  events=%d",
            incident.incident_id,
            score,
            incident.severity,
            incident.event_count,
        )

    incidents.sort(key=lambda i: i.risk_score, reverse=True)
    logger.info("Scoring complete. Top score: %d", incidents[0].risk_score if incidents else 0)
    return incidents

# Scoring logic


@dataclass
class _ScoreAccumulator:
    """Mutable scoring state for a single incident."""
    points: int = 0
    reasons: list[str] = None

    def __post_init__(self) -> None:
        """Inicializa la lista de razones como lista vacía.

        Necesario porque los campos mutables (listas, dicts) no pueden tener
        valores por defecto directos en dataclasses — se deben inicializar
        en __post_init__ para evitar que todas las instancias compartan el mismo objeto.
        """
        self.reasons = []

    def add(self, points: int, reason: str) -> None:
        """Acumula puntos y registra la razón asociada de forma atómica.

        Garantiza que cada incremento de puntos siempre tenga su razón
        explicativa correspondiente. Esto hace imposible agregar puntos
        sin dejar registro del motivo, lo cual es central para la
        explicabilidad del score final.

        Parámetros:
            points: Cantidad de puntos a sumar al acumulado. Siempre positivo.
            reason: Descripción legible del motivo del incremento.
        """
        self.points += points
        self.reasons.append(f"+{points} {reason}")


def _score(incident: Incident) -> tuple[int, list[str]]:
    """Calcula el score de riesgo de un incidente evaluando nueve señales independientes.

    Primero agrega valores a nivel de incidente (no solo del evento primario):
    busca si algún evento tiene PII, si alguno fue sospechoso, cuál es el máximo
    de registros afectados, cuál es el peor scope de sharing, etc. Luego evalúa
    cada señal y acumula puntos mediante _ScoreAccumulator. El score final se
    capea en MAX_SCORE para garantizar que siempre esté en el rango [0, 100].

    Señales evaluadas (en orden):
        1. Sensibilidad del dato (PII presente)
        2. Radio de exposición (sharing_scope más permisivo)
        3. Volumen de datos (máximo de records_affected)
        4. Señal de comportamiento (suspicious_activity)
        5. Acción exitosa confirmada (success + suspicious)
        6. Perfil de riesgo del servicio (BigQuery, IAM, Storage)
        7. Severidad de la acción ejecutada (make_public, export, download)
        8. Fortaleza de autenticación (password vs MFA/SSO)
        9. Profundidad de correlación (cantidad de eventos agrupados)

    Parámetros:
        incident: Incident con uno o más AuditEvents. El score se calcula
                  considerando todos los eventos, no solo el primario.

    Retorna:
        Tupla (score, reasons) donde score es un entero entre 0 y MAX_SCORE,
        y reasons es una lista de strings explicando cada punto acumulado.
    """
    acc = _ScoreAccumulator()
    primary = incident.primary_event

    # Aggregate signals across all events in the incident
    any_pii = any(e.contains_pii for e in incident.events)
    any_suspicious = any(e.event_type == "suspicious_activity" for e in incident.events)
    any_successful_suspicious = any(
        e.success and e.event_type == "suspicious_activity" for e in incident.events
    )
    max_records = max(e.records_affected for e in incident.events)
    worst_scope = _worst_sharing_scope(incident.events)
    any_high_risk_action = any(e.action.lower() in HIGH_RISK_ACTIONS for e in incident.events)
    any_weak_auth = any(e.authentication_method.lower() == "password" for e in incident.events)
    services = {e.service.lower() for e in incident.events}

    # Signal 1 — Data sensitivity
    if any_pii:
        acc.add(20, "Contains PII (data classified as Restricted)")

    # Signal 2 — Exposure radius
    if worst_scope == "public":
        acc.add(25, "Data exposed publicly (highest sharing scope)")
    elif worst_scope == "external":
        acc.add(15, "Data shared externally (outside organization)")
    elif worst_scope == "internal":
        acc.add(5, "Data shared internally")

    # Signal 3 — Data volume
    if max_records > 1_000:
        acc.add(25, f"Large volume of records affected ({max_records:,})")
    elif max_records > 100:
        acc.add(10, f"Significant number of records affected ({max_records:,})")
    elif max_records > 10:
        acc.add(5, f"Multiple records affected ({max_records:,})")

    # Signal 4 — Behavioral signal
    if any_suspicious:
        acc.add(15, "Suspicious activity detected by event classifier")

    # Signal 5 — Successful action
    if any_successful_suspicious:
        acc.add(10, "Suspicious action succeeded (confirmed exfiltration risk)")
    elif primary.success and any_high_risk_action:
        acc.add(5, "High-risk action completed successfully")

    # Signal 6 — Service risk profile
    if "bigquery" in services:
        acc.add(10, "Involves BigQuery (high-volume data export risk)")
    elif "iam" in services:
        acc.add(10, "Involves IAM (privilege escalation / credential risk)")
    elif services & MEDIUM_RISK_SERVICES:
        acc.add(5, "Involves Cloud Storage (data exposure risk)")

    # Signal 7 — Action severity
    if any(e.action.lower() == "make_public" for e in incident.events):
        acc.add(15, "Resource was made public")
    elif any(e.action.lower() in {"export", "policy_change"} for e in incident.events):
        acc.add(10, "High-risk action performed (export or policy change)")
    elif any(e.action.lower() in {"download", "share"} for e in incident.events):
        acc.add(8, "Data movement action performed (download or share)")

    # Signal 8 — Authentication strength
    if any_weak_auth:
        acc.add(5, "Weak authentication used (password only, no MFA/SSO)")

    # Signal 9 — Campaign indicator (correlation depth)
    if incident.event_count >= 5:
        acc.add(15, f"High-frequency campaign: {incident.event_count} correlated events")
    elif incident.event_count >= 3:
        acc.add(10, f"Multiple correlated events: {incident.event_count} events")
    elif incident.event_count == 2:
        acc.add(5, "Two related events correlated into a single incident")

    final_score = min(acc.points, MAX_SCORE)
    return final_score, acc.reasons


def _to_severity(score: int) -> str:
    """Convierte un score numérico a una etiqueta de severidad textual.

    Recorre el diccionario SEVERITY_THRESHOLDS de mayor a menor umbral
    y devuelve la primera etiqueta cuyo umbral sea menor o igual al score.
    Gracias al orden del dict (Critical → High → Medium → Low), el primer
    match siempre es el nivel correcto. Modificar los umbrales solo requiere
    editar SEVERITY_THRESHOLDS — esta función no necesita cambios.

    Parámetros:
        score: Entero entre 0 y MAX_SCORE resultado del cálculo de _score().

    Retorna:
        String con la severidad correspondiente: "Critical", "High", "Medium" o "Low".
    """
    for label, threshold in SEVERITY_THRESHOLDS.items():
        if score >= threshold:
            return label
    return "Low"


def _worst_sharing_scope(events: list[AuditEvent]) -> str:
    """Devuelve el sharing_scope más permisivo (peligroso) entre todos los eventos del incidente.

    Un incidente con múltiples eventos puede tener distintos niveles de sharing.
    Para el cálculo de riesgo se usa el peor caso: si algún evento fue público,
    el incidente completo se trata como público. Usa un dict de prioridades
    para hacer la comparación numérica y evitar lógica de strings frágil.

    Orden de peligrosidad: public (3) > external (2) > internal (1) > private (0).

    Parámetros:
        events: Lista de AuditEvent del incidente. Debe contener al menos un elemento.

    Retorna:
        String con el sharing_scope de mayor prioridad encontrado entre los eventos:
        "public", "external", "internal" o "private".
    """
    order = {"public": 3, "external": 2, "internal": 1, "private": 0}
    return max(events, key=lambda e: order.get(e.sharing_scope, 0)).sharing_scope
