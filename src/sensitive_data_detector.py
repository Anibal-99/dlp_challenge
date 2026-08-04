"""
Detector local de datos sensibles para el pipeline DLP.

Detecta tres categorías de información que el RFC de Colibrí clasifica como
Restringido y requieren protección en el programa DLP:

  Categoría 1 — PII (Personally Identifiable Information)
      Datos que identifican directamente a una persona física.
      Marco regulatorio: Ley 25.326 (Argentina), GDPR.
      Tipos: EMAIL_ADDRESS, PHONE_LATAM, DNI_ARGENTINA

  Categoría 2 — PCI (Payment Card Industry)
      Datos de tarjetas de pago. Son datos financieros, no datos personales —
      identifican una cuenta, no una persona. Tienen su propio estándar regulatorio.
      Marco regulatorio: PCI DSS (Visa / Mastercard / Amex).
      Tipos: CREDIT_CARD, IBAN

  Categoría 3 — Credentials / Secrets
      Credenciales de infraestructura. No son datos personales ni datos de pago —
      son secretos técnicos cuya exposición compromete sistemas completos.
      Marco regulatorio: no hay un estándar único; es postura de seguridad.
      Tipos: JWT_TOKEN, GCP_PRIVATE_KEY

Las tres categorías se detectan en este módulo porque el RFC las agrupa bajo el
mismo nivel de clasificación (Restringido) y la pérdida de cualquiera de ellas
representa un riesgo crítico para Colibrí. El nombre del campo en AuditEvent
(contains_pii) es heredado del dataset y refleja la terminología del upstream
(Google Cloud DLP), que usa "PII" como término paraguas para todos los datos
sensibles. Este detector mantiene esa convención para compatibilidad.

Relación con Google Cloud DLP:
    En producción, los InfoTypes de Cloud DLP reemplazan este módulo para
    operar a escala con modelos entrenados. Este detector sirve como:
      - Fallback para entornos sin acceso a Cloud DLP
      - Segunda opinión sobre clasificaciones del upstream
      - Demostración de la lógica de detección multi-señal del RFC
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Configuración — modificar aquí sin tocar la lógica
MIN_CONFIDENCE: float = 0.6
"""Umbral mínimo de confianza para marcar una detección como positiva.
Valores más altos = menos falsos positivos, más falsos negativos."""

# Score base diferenciado por tipo.
# Los patrones más específicos (que casi no producen falsos positivos por sí solos)
# tienen score base más alto. Los patrones genéricos (números, emails) requieren
# contexto adicional para superar el umbral.
_TYPE_BASE_SCORES: dict[str, float] = {
    "GCP_PRIVATE_KEY": 0.70,  # Patrón extremadamente específico; cualquier match es crítico
    "JWT_TOKEN":       0.50,  # eyJ... es un prefijo inequívoco de un JWT
    "CREDIT_CARD":     0.35,  # Requiere Luhn + contexto para alta confianza
    "IBAN":            0.35,  # Requiere validación de longitud + contexto
    "EMAIL_ADDRESS":   0.35,  # Común en texto legítimo; necesita contexto
    "PHONE_LATAM":     0.30,  # Secuencias numéricas frecuentes; necesita contexto
    "DNI_ARGENTINA":   0.30,  # Patrones de 8 dígitos frecuentes; necesita contexto
}

VALIDATION_BONUS: float = 0.15
"""Bonus adicional cuando el match pasa una validación estructural (Luhn, longitud IBAN)."""

CONTEXT_BONUS_PER_KEYWORD: float = 0.10
"""Puntos por cada keyword de contexto encontrada cerca del match (máximo 2 keywords)."""

CONTEXT_WINDOW_CHARS: int = 60
"""Distancia en caracteres alrededor del match dentro de la cual se buscan keywords."""

# Patrones de detección
_PATTERNS: dict[str, re.Pattern[str]] = {
    "CREDIT_CARD": re.compile(
        r"\b(?:"
        r"4[0-9]{12}(?:[0-9]{3})?"       # Visa (13 o 16 dígitos)
        r"|5[1-5][0-9]{14}"               # Mastercard
        r"|3[47][0-9]{13}"                # American Express
        r"|6(?:011|5[0-9]{2})[0-9]{12}"  # Discover
        r")\b"
    ),
    "EMAIL_ADDRESS": re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
    ),
    "PHONE_LATAM": re.compile(
        r"\b(?:\+?54[\s.\-]?)?(?:9[\s.\-]?)?"
        r"(?:11|[2-9]\d{1,3})[\s.\-]?\d{4}[\s.\-]?\d{4}\b"
    ),
    "DNI_ARGENTINA": re.compile(
        r"\b\d{2}\.?\d{3}\.?\d{3}\b"
    ),
    "IBAN": re.compile(
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b"
    ),
    "JWT_TOKEN": re.compile(
        r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"
    ),
    "GCP_PRIVATE_KEY": re.compile(
        r"-----BEGIN (?:RSA )?PRIVATE KEY-----|"
        r'"type"\s*:\s*"service_account"'
    ),
}

# Keywords que, si aparecen cerca de un match, aumentan la confianza.
# Representa el "contexto" que hace más creíble que el match sea PII real
# y no un falso positivo numérico o lexicográfico.
_CONTEXT_KEYWORDS: dict[str, list[str]] = {
    "CREDIT_CARD":     ["tarjeta", "crédito", "débito", "cvv", "cvc", "vencimiento", "card", "pan"],
    "EMAIL_ADDRESS":   ["correo", "email", "mail", "contacto", "usuario"],
    "PHONE_LATAM":     ["teléfono", "celular", "móvil", "tel", "phone", "contacto"],
    "DNI_ARGENTINA":   ["dni", "documento", "cédula", "identidad", "nacional"],
    "IBAN":            ["iban", "cuenta", "bancaria", "transferencia", "bank", "cbu"],
    "JWT_TOKEN":       ["token", "jwt", "bearer", "auth", "authorization"],
    "GCP_PRIVATE_KEY": ["key", "clave", "privada", "service_account", "credentials", "secret"],
}


# Resultado
@dataclass
class PIIDetectionResult:
    """Resultado de la detección de PII sobre un fragmento de texto.

    Atributos:
        detected:   True si el score de confianza alcanza o supera MIN_CONFIDENCE.
        confidence: Score acumulado entre 0.0 y 1.0.
        pii_types:  Lista de los nombres de tipos de PII encontrados en el texto.
    """
    detected: bool
    confidence: float
    pii_types: list[str] = field(default_factory=list)


# TODO: diseñar una funcion que utilice los patrones basicos y me permita descartar un FP
def detect_pii(text: str) -> PIIDetectionResult:
    """Analiza un texto y devuelve los tipos de PII detectados con su score de confianza.

    Para cada tipo de PII definido en _PATTERNS:
      1. Busca matches con el regex correspondiente.
      2. Si aplica, valida el match con checksum (Luhn para tarjetas, longitud para IBAN).
         Los matches que no pasan la validación se descartan — esto es lo que diferencia
         este detector de un simple grep y reduce los falsos positivos.
      3. Acumula puntos de confianza: BASE_SCORE + VALIDATION_BONUS si aplica.
      4. Busca keywords de contexto en los CONTEXT_WINDOW_CHARS caracteres alrededor
         del primer match y agrega CONTEXT_BONUS_PER_KEYWORD por cada una encontrada.
    Al final, si se detectaron múltiples tipos de PII distintos, se agrega un bonus
    por diversidad, ya que la coexistencia de varios tipos en el mismo texto es una
    señal más fuerte de que el dato es sensible.

    Parámetros:
        text: Texto libre a analizar (event_description, nombre de recurso, etc.).
              Puede ser vacío o None — en ese caso devuelve resultado negativo.

    Retorna:
        PIIDetectionResult con detected=True si confidence >= MIN_CONFIDENCE,
        el score acumulado y la lista de tipos encontrados.
    """
    if not text or not text.strip():
        return PIIDetectionResult(detected=False, confidence=0.0)

    text_lower = text.lower()
    total_confidence = 0.0
    detected_types: list[str] = []

    for pii_type, pattern in _PATTERNS.items():
        matches = pattern.findall(text)
        if not matches:
            continue

        type_confidence = _TYPE_BASE_SCORES.get(pii_type, 0.35)

        # Validación de checksum para tarjetas de crédito
        if pii_type == "CREDIT_CARD":
            valid = [m for m in matches if _luhn_check(re.sub(r"\D", "", m))]
            if not valid:
                continue  # Descarta matches que no pasan Luhn
            type_confidence += VALIDATION_BONUS

        # Validación de longitud para IBAN
        if pii_type == "IBAN":
            valid = [m for m in matches if _iban_check(m)]
            if not valid:
                continue
            type_confidence += VALIDATION_BONUS

        # Boost por keywords de contexto cercanas al primer match
        first_match = pattern.search(text)
        if first_match:
            surrounding = text_lower[
                max(0, first_match.start() - CONTEXT_WINDOW_CHARS):
                first_match.end() + CONTEXT_WINDOW_CHARS
            ]
            keywords_found = sum(
                1 for kw in _CONTEXT_KEYWORDS.get(pii_type, [])
                if kw in surrounding
            )
            type_confidence += min(keywords_found, 2) * CONTEXT_BONUS_PER_KEYWORD

        total_confidence += type_confidence
        detected_types.append(pii_type)

    # Bonus por diversidad: múltiples tipos de PII en el mismo texto = señal más fuerte
    if len(detected_types) > 1:
        total_confidence += 0.10

    final_confidence = min(round(total_confidence, 3), 1.0)
    return PIIDetectionResult(
        detected=final_confidence >= MIN_CONFIDENCE,
        confidence=final_confidence,
        pii_types=detected_types,
    )


# Validaciones estructurales
def _luhn_check(number: str) -> bool:
    """Valida un número usando el algoritmo de Luhn (checksum de tarjetas de crédito).

    El algoritmo de Luhn es el estándar ISO/IEC 7812 usado por todas las
    redes de tarjetas (Visa, Mastercard, Amex) para detectar errores de
    tipeo y descartar números generados aleatoriamente. Un regex solo
    verifica el formato; Luhn verifica que el número sea matemáticamente
    válido — es la diferencia entre detectar "4111111111111111" (válida)
    y "4111111111111112" (inválida aunque tiene el formato correcto).

    Parámetros:
        number: String con solo dígitos (sin guiones ni espacios).

    Retorna:
        True si el número pasa el checksum de Luhn. False en caso contrario.
    """
    if not number.isdigit() or len(number) < 13:
        return False
    digits = [int(d) for d in number]
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits) + sum(
        d * 2 - 9 if d * 2 > 9 else d * 2
        for d in even_digits
    )
    return total % 10 == 0


def _iban_check(iban: str) -> bool:
    """Valida un IBAN usando el algoritmo de checksum mod-97 definido en ISO 13616.

    El algoritmo funciona en tres pasos:
      1. Mover los primeros 4 caracteres al final del string.
      2. Reemplazar cada letra por su valor numérico (A=10, B=11, ..., Z=35),
         produciendo un número entero de hasta ~34 dígitos.
      3. Calcular ese número módulo 97. Si el resultado es 1, el IBAN es válido.

    Python maneja enteros de precisión arbitraria de forma nativa, por lo que
    no se necesita ninguna librería externa para operar con números de 34 dígitos.

    Parámetros:
        iban: String con el código IBAN detectado (con o sin espacios).

    Retorna:
        True si el IBAN pasa el checksum mod-97 y tiene longitud válida (15–34).
        False si el formato es inválido o el checksum no coincide.
    """
    normalized = iban.replace(" ", "").upper()

    if not (15 <= len(normalized) <= 34):
        return False

    # Mover los primeros 4 caracteres al final
    rearranged = normalized[4:] + normalized[:4]

    # Reemplazar letras por sus valores numéricos (A=10 ... Z=35)
    numeric = "".join(
        str(ord(ch) - ord("A") + 10) if ch.isalpha() else ch
        for ch in rearranged
    )

    return int(numeric) % 97 == 1
