"""
Core data models for the DLP pipeline.

AuditEvent  — one normalized event from either input format.
Incident    — one or more correlated events with computed risk metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class AuditEvent:
    """A single normalized audit log entry.

    Produced by the parser from either JSON or CSV input.
    All downstream modules operate exclusively on this type.
    """

    event_id: int
    timestamp: datetime
    service: str
    user_email: str
    action: str
    resource_name: str
    resource_type: str
    contains_pii: bool
    pii_types: str
    records_affected: int
    destination: str
    sharing_scope: str          # public | external | internal | private
    success: bool
    ip_address: str
    country: str
    severity: str
    event_type: str             # suspicious_activity | normal_activity
    file_size: int
    download_time: int
    user_role: str              # admin | manager | user
    source_device: str
    authentication_method: str  # MFA | SSO | password
    data_center_location: str
    event_description: str
    event_category: str
    event_source: str


@dataclass
class Incident:
    """A correlated group of one or more AuditEvents with risk metadata.

    Produced by the correlator, enriched by the scorer, and consumed by the exporter.
    """

    incident_id: str
    events: list[AuditEvent]

    # Populated by the scorer
    risk_score: int = 0
    severity: str = ""          # Low | Medium | High | Critical
    reasons: list[str] = field(default_factory=list)

    @property
    def primary_event(self) -> AuditEvent:
        """Devuelve el evento más temprano del incidente.

        Se usa como registro representativo cuando el reporte necesita
        mostrar un único valor (usuario, recurso, timestamp) para un
        incidente que puede contener múltiples eventos correlacionados.

        Retorna:
            AuditEvent con el timestamp más antiguo dentro de self.events.
        """
        return min(self.events, key=lambda e: e.timestamp)

    @property
    def user_email(self) -> str:
        """Devuelve el email del usuario del evento primario del incidente.

        Retorna:
            String con el email en minúsculas del usuario más temprano.
        """
        return self.primary_event.user_email

    @property
    def resource_name(self) -> str:
        """Devuelve el nombre del recurso involucrado en el evento primario.

        Retorna:
            String con el nombre del recurso del evento más temprano.
        """
        return self.primary_event.resource_name

    @property
    def service(self) -> str:
        """Devuelve el servicio de GCP o Workspace del evento primario.

        Retorna:
            String con el nombre del servicio (ej. 'BigQuery', 'IAM').
        """
        return self.primary_event.service

    @property
    def timestamp(self) -> datetime:
        """Devuelve el timestamp del evento más temprano del incidente.

        Retorna:
            Objeto datetime con timezone UTC del evento primario.
        """
        return self.primary_event.timestamp

    @property
    def event_count(self) -> int:
        """Devuelve la cantidad de eventos que componen el incidente.

        Un valor mayor a 1 indica que el correlator agrupó múltiples
        eventos relacionados en este incidente.

        Retorna:
            Entero con la cantidad de AuditEvents en self.events.
        """
        return len(self.events)
