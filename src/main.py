"""
DLP Pipeline — entry point.

Usage:
    python src/main.py data/logs_json_cloud_audit.json
    python src/main.py data/logs_csv_cloud_audit.csv

Pipeline stages:
    1. Parse    — load and normalize events from JSON or CSV
    2. Correlate — group related events into incidents
    3. Score    — compute risk score, severity, and reasons per incident
    4. Export   — write prioritized_incidents.csv to output/
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

# Allow imports from src/ when running as: python src/main.py
sys.path.insert(0, str(Path(__file__).parent))

from correlator import correlate
from exporter import export
from parser import load_events
from scorer import score_incidents


def _configure_logging(verbose: bool) -> None:
    """Configura el sistema de logging de Python para toda la aplicación.

    Establece el nivel de log y el formato de los mensajes. Si verbose es True,
    activa el nivel DEBUG, que muestra el score individual de cada incidente durante
    el proceso de scoring. Si es False, solo muestra mensajes INFO con el resumen
    por etapa visible en la terminal durante una ejecución normal.

    Parámetros:
        verbose: Si True, activa logs de nivel DEBUG. Si False, solo muestra INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )


def _parse_args() -> argparse.Namespace:
    """Define y parsea los argumentos de la interfaz de línea de comandos.

    Configura tres argumentos: el archivo de input obligatorio, el path de
    output opcional y el flag --verbose para activar logs de debug. argparse
    maneja automáticamente los mensajes de error y el texto de ayuda (--help).

    Retorna:
        Namespace de argparse con los atributos input_file (str), output (str)
        y verbose (bool) listos para ser consumidos por main().
    """
    parser = argparse.ArgumentParser(
        description="DLP Audit Log Analyzer — reads security logs, correlates events, "
        "scores risk, and exports a prioritized incident report.",
    )
    parser.add_argument(
        "input_file",
        help="Path to the audit log file (.json or .csv)",
    )
    parser.add_argument(
        "--output",
        default="output/prioritized_incidents.csv",
        help="Destination path for the output CSV (default: output/prioritized_incidents.csv)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug-level logging",
    )
    return parser.parse_args()


def _stage(name: str) -> "_StageTimer":
    """Crea un context manager que loguea el inicio y la duración de una etapa del proceso de DLP.

    Diseñado para usarse con la sentencia `with`, de forma que el nombre de la
    etapa se loguea al entrar y el tiempo transcurrido al salir, sin necesidad
    de escribir ese boilerplate en cada etapa de main().

    Parámetros:
        name: Nombre descriptivo de la etapa, usado en el mensaje de log.

    Retorna:
        Instancia de _StageTimer lista para ser usada como context manager.
    """
    return _StageTimer(name)


class _StageTimer:
    def __init__(self, name: str) -> None:
        self.name = name
        self._start = 0.0

    def __enter__(self) -> "_StageTimer":
        """Registra el inicio de la etapa y guarda el timestamp de comienzo.

        Se ejecuta automáticamente al entrar al bloque `with`. Loguea el nombre
        de la etapa y captura el tiempo de inicio con perf_counter(), que ofrece
        mayor precisión que time.time() para medir duraciones cortas.

        Retorna:
            La propia instancia de _StageTimer (no se usa en la práctica).
        """
        logger = logging.getLogger(__name__)
        logger.info("── %s", self.name)
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_) -> None:
        """Calcula y loguea el tiempo transcurrido al finalizar la etapa.

        Se ejecuta automáticamente al salir del bloque `with`, tanto si la etapa
        terminó correctamente como si lanzó una excepción. El parámetro *_ captura
        los argumentos de excepción que Python pasa a __exit__ y los ignora,
        dejando que cualquier excepción se propague normalmente hacia main().

        Parámetros:
            *_: Tipo, valor y traceback de la excepción (ignorados intencionalmente).
        """
        elapsed = time.perf_counter() - self._start
        logger = logging.getLogger(__name__)
        logger.info("   done in %.3fs", elapsed)


def main() -> None:
    """Punto de entrada del DLP. Orquesta las cuatro etapas en secuencia.

    Parsea los argumentos de CLI, configura el logging y ejecuta las etapas
    parse → correlate → score → export dentro de un bloque try/except que
    captura los errores conocidos (archivo no encontrado, formato inválido) y
    los errores inesperados por separado, logueando un mensaje claro en cada caso
    y saliendo con código 1 para que scripts externos puedan detectar el fallo.
    Al finalizar exitosamente imprime un resumen con el conteo de incidentes
    por severidad y la ruta del archivo generado.

    No recibe parámetros (lee argv directamente via _parse_args).
    No retorna valor (termina con sys.exit(1) en caso de error).
    """
    args = _parse_args()
    _configure_logging(args.verbose)
    log = logging.getLogger(__name__)

    log.info("DLP starting")
    log.info("Input : %s", args.input_file)
    log.info("Output: %s", args.output)

    try:
        with _stage("Stage 1 — Parse"):
            events = load_events(args.input_file)

        with _stage("Stage 2 — Correlate"):
            incidents = correlate(events)

        with _stage("Stage 3 — Score"):
            incidents = score_incidents(incidents)

        with _stage("Stage 4 — Export"):
            output_path = export(incidents, output_path=args.output)

    except FileNotFoundError as exc:
        log.error("Input file not found: %s", exc)
        sys.exit(1)
    except ValueError as exc:
        log.error("Input error: %s", exc)
        sys.exit(1)
    except Exception as exc:
        log.exception("Unexpected error: %s", exc)
        sys.exit(1)

    # Summary
    critical = sum(1 for i in incidents if i.severity == "Critical")
    high = sum(1 for i in incidents if i.severity == "High")
    medium = sum(1 for i in incidents if i.severity == "Medium")
    low = sum(1 for i in incidents if i.severity == "Low")

    log.info("──────────────────────────────────────")
    log.info("Incidents : %d total", len(incidents))
    log.info("  Critical: %d", critical)
    log.info("  High    : %d", high)
    log.info("  Medium  : %d", medium)
    log.info("  Low     : %d", low)
    log.info("Report    : %s", output_path)
    log.info("──────────────────────────────────────")


if __name__ == "__main__":
    main()
