# DLP Operations — Colibrí

Guía operacional del programa de Data Loss Prevention para el equipo de Data Security.

Cubre los casos de alerta de mayor valor, el flujo de triage y escalamiento, y los KPIs del área.

---

## Índice

1. [Casos de alerta de alto valor](#1-casos-de-alerta-de-alto-valor)
2. [Flujo de triage y escalamiento](#2-flujo-de-triage-y-escalamiento)
3. [KPIs del área](#3-kpis-del-área)

---

## 1. Casos de alerta de alto valor

Los siete casos fueron seleccionados en base a los incidentes históricos de Colibrí y al modelo de clasificación del RFC. Están ordenados por impacto potencial.

Cada caso incluye: qué se detecta, por qué importa, cómo se responde y qué se puede automatizar.

---

### ALERT-01 — Export de BigQuery con sharing público

**Superficie:** BigQuery → Google Drive / Sheets  
**Severidad base:** Critical

**Qué detecta:**  
Una query en BigQuery que exporta resultados a un Google Sheet configurado con acceso `anyone with the link` o `public on the web`. Particularmente grave cuando la tabla de origen contiene columnas clasificadas como Restringido (PII, datos financieros, score crediticio).

**Por qué es el caso más peligroso:**  
Es el near-miss más documentado en Colibrí. Un export de BigQuery puede filtrar millones de registros de clientes en una sola operación. El sharing público hace que el dato quede indexable por motores de búsqueda externos.

**Señales de detección:**
- Cloud Audit Log: `bigquery.jobs.create` con `destinationTable` en Drive o Sheets
- Google Drive Audit Log: `change_acl_editors` → `anyone` o `allUsers` sobre el archivo destino
- Cloud DLP scan del archivo destino: clasificación Restringido

**Respuesta:**

| Paso | Acción | Responsable |
|---|---|---|
| 1 | Revocar el sharing público del archivo (API Drive) | Automatizado |
| 2 | Notificar al usuario con link a política de datos | Automatizado |
| 3 | Abrir ticket de investigación con los metadatos del export | Automatizado |
| 4 | Revisar si el archivo fue accedido externamente antes de la revocación (Drive activity log) | Analista L2 |
| 5 | Determinar si fue error, workaround de proceso o intención maliciosa | Analista L2 |
| 6 | Si hay evidencia de acceso externo: activar protocolo de brecha | CISO + Legal |

**Automatización posible:**  
Google Workspace Alert Center + Cloud Functions: detectar el evento de ACL change, revocar automáticamente en < 2 minutos y abrir el ticket.

---

### ALERT-02 — Service Account Key expuesta en documento compartido

**Superficie:** Google Drive / Google Docs  
**Severidad base:** Critical

**Qué detecta:**  
Una Service Account Key (archivo JSON con `"type": "service_account"`) o un fragmento de texto que contenga el patrón de una SA key (`-----BEGIN RSA PRIVATE KEY-----`) en un documento de Drive con sharing distinto de `private` o `domain only`.

**Por qué es crítico:**  
Una SA key expuesta es una credencial permanente. A diferencia de una contraseña de usuario, no tiene MFA — quien la tiene puede autenticarse como el servicio en GCP indefinidamente hasta que sea desactivada. Si el servicio tiene roles de producción (BigQuery Data Viewer, Storage Object Admin), la exposición es equivalente a una brecha directa.

**Señales de detección:**
- Cloud DLP InfoType: `GCP_CREDENTIALS`, `JSON_WEB_TOKEN`
- Drive Audit Log: archivo con `mimeType=application/json` o `text/plain` compartido externamente
- IAM Audit Log: `google.iam.admin.v1.CreateServiceAccountKey` seguido de sharing externo en Drive (correlación temporal)

**Respuesta:**

| Paso | Acción | Responsable |
|---|---|---|
| 1 | Deshabilitar la SA key en IAM (`gcloud iam service-accounts keys disable`) | Automatizado |
| 2 | Revocar el sharing del documento | Automatizado |
| 3 | Revisar los logs de uso de la key en Cloud Audit Logs (últimas 72h) | Analista L2 |
| 4 | Determinar si la key fue usada desde IPs o user agents inusuales | Analista L2 |
| 5 | Rotar la key y actualizar el secreto en Secret Manager | Owner del servicio |
| 6 | Si hay uso sospechoso: revocar todos los tokens activos del service account | CISO + SRE |

**Automatización posible:**  
Cloud DLP + Pub/Sub + Cloud Functions: al detectar credencial en Drive, deshabilitar la key en < 5 minutos. No se elimina — se deshabilita primero para evitar romper servicios hasta confirmar el impacto.

---

### ALERT-03 — PII o datos financieros reenviados a correo personal

**Superficie:** Gmail  
**Severidad base:** High / Critical según volumen

**Qué detecta:**  
Un email enviado desde una cuenta corporativa (`@colibri.com`) hacia un dominio externo personal (`gmail.com`, `hotmail.com`, `yahoo.com`, etc.) que contiene adjuntos o cuerpo con datos clasificados como Restringido: números de tarjeta, IBAN, DNI, nombre + email + teléfono en conjunto.

**Por qué importa:**  
El patrón clásico de exfiltración insider. Especialmente relevante en procesos de offboarding o cuando un empleado está en proceso de salida. Un solo email puede contener miles de registros de clientes en un CSV adjunto.

**Señales de detección:**
- Gmail Log: `message_destination` con dominio no corporativo
- Cloud DLP scan del adjunto o cuerpo: `CREDIT_CARD_NUMBER`, `IBAN_CODE`, `ARGENTINA_DNI_NUMBER`, `EMAIL_ADDRESS` + `PHONE_NUMBER` en conjunto (combinación = mayor confianza)
- Señal de comportamiento: volumen de adjuntos enviados externamente superior al baseline del usuario (últimos 30 días)

**Respuesta:**

| Paso | Acción | Responsable |
|---|---|---|
| 1 | Poner el email en cuarentena si aún no fue entregado (Gmail DLP policy) | Automatizado |
| 2 | Si ya fue entregado: notificar al manager del usuario y a Data Security | Automatizado |
| 3 | Revisar el historial de emails externos del usuario (últimos 30 días) | Analista L2 |
| 4 | Verificar si el usuario está en proceso de offboarding (cruce con HR) | Analista L2 |
| 5 | Si el patrón sugiere intención: suspender la cuenta hasta investigación | CISO + RRHH |
| 6 | Documentar para posible acción legal o regulatoria | Legal |

**Automatización posible:**  
Gmail Content Compliance rules: bloquear emails a dominios externos que contengan patrones de tarjeta o adjuntos CSV/Excel con más de N filas. Requiere calibrar para evitar falsos positivos en reportes legítimos.

---

### ALERT-04 — Bucket de Cloud Storage con acceso público

**Superficie:** Cloud Storage  
**Severidad base:** Critical si contiene datos clasificados / High si está vacío

**Qué detecta:**  
Un bucket de GCS configurado con `allUsers` o `allAuthenticatedUsers` en su IAM policy, especialmente si contiene objetos con datos clasificados como Confidencial o Restringido.

**Por qué importa:**  
Un bucket público es indexable. Herramientas de reconocimiento como GrayhatWarfare indexan buckets GCS públicos. Si el bucket contiene backups, exports de BigQuery o archivos de modelo crediticio, el dato queda expuesto permanentemente hasta que alguien lo note.

**Señales de detección:**
- Cloud Audit Log: `storage.setIamPolicy` con `allUsers` o `allAuthenticatedUsers`
- Cloud Asset Inventory: escaneo periódico de buckets con `publicAccessPrevention = inherited`
- Cloud DLP scan del bucket: clasificación del contenido

**Respuesta:**

| Paso | Acción | Responsable |
|---|---|---|
| 1 | Remover el binding público de la IAM policy del bucket | Automatizado |
| 2 | Activar `publicAccessPrevention = enforced` en el bucket | Automatizado |
| 3 | Revisar los access logs del bucket (últimas 48h) para detectar accesos externos | Analista L2 |
| 4 | Clasificar el contenido del bucket con Cloud DLP si no está clasificado | Analista L2 |
| 5 | Identificar quién hizo el cambio de IAM y por qué | Analista L2 |
| 6 | Si hubo acceso externo a datos Restringidos: activar protocolo de brecha | CISO + Legal |

**Automatización posible:**  
Security Command Center + Cloud Functions: reactive policy enforcement. Al detectar el cambio de IAM, revertir automáticamente y notificar al owner del bucket.

---

### ALERT-05 — Escalada de privilegios en IAM seguida de acceso a datos

**Superficie:** Cloud IAM + BigQuery / Cloud Storage  
**Severidad base:** High / Critical

**Qué detecta:**  
Un patrón en dos pasos correlacionados: (1) un usuario o SA recibe un rol de alto privilegio (`roles/bigquery.dataViewer`, `roles/storage.objectAdmin`, `roles/iam.securityAdmin`) y (2) dentro de una ventana corta (< 2 horas) accede a recursos clasificados como Restringido o ejecuta una query de alto volumen.

**Por qué importa:**  
La combinación de privilege escalation + data access inmediato es la firma de un ataque en progreso o de un insider aprovechando un permiso temporal. Un solo cambio de IAM mal revisado puede abrir el acceso a toda la data warehouse de clientes.

**Señales de detección:**
- IAM Audit Log: `SetIamPolicy` o `CreateServiceAccountKey` (signal 1)
- BigQuery / Storage Audit Log: `bigquery.jobs.create` o `storage.objects.get` desde el mismo principal (signal 2)
- Correlación temporal: < 2 horas entre ambos eventos
- Contexto adicional: si el IAM change lo hizo el mismo usuario que luego accede (auto-escalada) → severidad máxima

**Respuesta:**

| Paso | Acción | Responsable |
|---|---|---|
| 1 | Alerta inmediata a Data Security con ambos eventos correlacionados | Automatizado |
| 2 | Revisar si el IAM change fue aprobado (tiene ticket/PR asociado) | Analista L2 |
| 3 | Revisar qué datos accedió y el volumen | Analista L2 |
| 4 | Si el change no fue aprobado: revocar el rol y suspender la sesión | Analista L2 |
| 5 | Auditoría de todos los cambios de IAM del usuario en los últimos 30 días | Analista L2 |
| 6 | Si hay patrón sistemático: elevar a CISO y considerar acción legal | CISO |

**Automatización posible:**  
Correlación en tiempo real via Cloud Logging + Pub/Sub. El challenge es que requiere unir dos streams de logs distintos. Implementable con Dataflow o con una Cloud Function con estado (Firestore como memoria).

---

### ALERT-06 — Descarga masiva de PII fuera del horario habitual

**Superficie:** Google Drive / BigQuery  
**Severidad base:** High

**Qué detecta:**  
Un usuario descarga o exporta un volumen de registros significativamente superior a su baseline personal (calculado sobre los últimos 30 días), en un horario fuera de su patrón habitual (madrugada, fin de semana) o desde una ubicación o dispositivo inusual.

**Por qué importa:**  
El volumen y el contexto temporal son señales de comportamiento que complementan al contenido. Un analista que normalmente descarga 100 registros y de repente descarga 50.000 a las 2 AM desde un IP en otro país es una anomalía clara, aunque el dato en sí sea de su dominio de trabajo.

**Señales de detección:**
- Drive Audit Log: `download` con `file_size` muy superior al baseline
- BigQuery Audit Log: `bigquery.jobs.create` con `totalBytesProcessed` elevado + timestamp fuera de horario
- Señal de contexto: IP en país distinto al habitual del usuario
- Señal de contexto: dispositivo no registrado (si hay MDM)

**Respuesta:**

| Paso | Acción | Responsable |
|---|---|---|
| 1 | Alerta al analista L2 con el contexto de comportamiento | Automatizado |
| 2 | Verificar si el usuario tenía una actividad planificada justificada | Analista L2 |
| 3 | Contactar al usuario y/o su manager para confirmar legitimidad | Analista L2 |
| 4 | Si no hay justificación: revocar sesión activa y bloquear account | Analista L2 |
| 5 | Revisar si los datos descargados aparecen en servicios externos (threat intel) | Analista L2 |

**Automatización posible:**  
Requiere construir un baseline por usuario. Implementable con BigQuery + Cloud Logging: una tabla de baseline que se actualiza diariamente y una Cloud Function que compara cada evento contra el percentil 95 del usuario.

---

### ALERT-07 — Regla de reenvío automático en Gmail a dominio externo

**Superficie:** Gmail  
**Severidad base:** High

**Qué detecta:**  
La creación o modificación de una regla de Gmail que reenvía automáticamente emails a una dirección externa (no `@colibri.com`). Este vector es especialmente peligroso porque opera silenciosamente y en tiempo real — cada email que llega al usuario es copiado al atacante.

**Por qué importa:**  
Es el mecanismo favorito de Business Email Compromise (BEC) y de insiders que quieren exfiltrar comunicaciones sin dejar rastro visible. Una sola regla puede exfiltrar meses de comunicaciones financieras y operativas.

**Señales de detección:**
- Gmail Audit Log: `email_forwarding_out_of_domain` = `true`
- Google Workspace Admin Log: `CREATE_EMAIL_ROUTE` con destino externo
- Señal adicional: si el usuario también tuvo un login desde una IP inusual en las últimas 24h → posible account takeover

**Respuesta:**

| Paso | Acción | Responsable |
|---|---|---|
| 1 | Deshabilitar la regla de reenvío inmediatamente (Admin SDK) | Automatizado |
| 2 | Verificar si hubo login sospechoso que pueda indicar account takeover | Automatizado |
| 3 | Si hay indicios de ATO: forzar reset de contraseña + revocar sesiones | Automatizado |
| 4 | Revisar el historial de emails reenviados (volume y contenido) | Analista L2 |
| 5 | Notificar al usuario para confirmar si la regla fue creada por ellos | Analista L2 |
| 6 | Si fue ATO: investigar el vector de compromiso (phishing, credential stuffing) | CISO + IT Security |

**Automatización posible:**  
Google Workspace Alert Center genera este evento nativo. Se puede conectar directamente a un webhook que ejecute la deshabilitación automática via Admin SDK sin intervención manual.

---

## 2. Flujo de triage y escalamiento

### Principios

- **Velocidad sobre perfección en contención:** ante una alerta Critical, contener primero (revocar acceso, deshabilitar key, bloquear email) y luego investigar. El costo de un falso positivo (usuario molesto por unos minutos) es menor al costo de una brecha real.
- **Todo incidente tiene un owner:** ninguna alerta puede quedar sin asignación después de 15 minutos de generada.
- **La automatización maneja el volumen, los humanos manejan el criterio:** las acciones repetibles y de bajo riesgo se automatizan. Las decisiones con impacto en usuarios reales requieren un analista.

---

### Niveles de severidad y SLAs

| Severidad | Definición | Tiempo de respuesta inicial | Tiempo de contención |
|---|---|---|---|
| **Critical** | Dato Restringido expuesto externamente o credencial comprometida | < 15 min | < 1 hora |
| **High** | Exposición potencial confirmada, sin evidencia de acceso externo aún | < 1 hora | < 4 horas |
| **Medium** | Comportamiento anómalo sin exposición confirmada | < 4 horas | < 24 horas |
| **Low** | Violación de política sin dato sensible involucrado | < 24 horas | Próximo sprint |

---

### Flujo de triage

```
ALERTA GENERADA
      │
      ▼
[Automatización — Tier 0]
  Enriquecer la alerta:
  • ¿Quién es el usuario? (rol, área, antigüedad, offboarding?)
  • ¿Qué recurso está involucrado? (clasificación del dato)
  • ¿Hubo eventos relacionados en las últimas 2h? (correlación)
  • Asignar severidad preliminar
      │
      ▼
  ¿Es Critical?
  ├── SÍ → Ejecutar contención automática (revocar, bloquear, deshabilitar)
  │         Notificar a analista L2 con contexto completo
  │         Abrir incidente en sistema de tickets
  └── NO → Encolar para revisión L1 (siguiente turno si es nocturno)
      │
      ▼
[Analista L1 — Tier 1]
  Revisar alerta dentro del SLA de severidad
  Determinar si es:
  ├── Falso positivo → Cerrar con documentación. Ajustar regla si es recurrente.
  ├── True positive bajo riesgo → Remediar y cerrar
  └── True positive con riesgo elevado → Escalar a L2
      │
      ▼
[Analista L2 — Tier 2]  (Data Security Senior)
  Investigación profunda:
  • Revisar logs adicionales (Drive activity, IAM, BigQuery)
  • Determinar scope: ¿cuántos registros? ¿hubo acceso externo confirmado?
  • Entrevistar al usuario si aplica
  • Decidir:
  ├── Contener y cerrar → documentar lecciones aprendidas
  ├── Requiere acción de RRHH → escalar con evidencia
  └── Posible brecha regulatoria → escalar a L3
      │
      ▼
[L3 — Escalamiento ejecutivo]  (CISO + Legal + Compliance)
  Se activa cuando:
  • Hay evidencia de acceso externo a datos de clientes (posible breach notification)
  • El incidente involucra a un empleado con acceso privilegiado
  • Hay indicios de un actor externo (ATO, credential stuffing)
  • El regulador local requiere notificación (según PDPA/regulación aplicable)
  
  Acciones:
  • Activar plan de respuesta a incidentes (IRP)
  • Evaluar obligación de notificación a clientes o reguladores
  • Preservar evidencia forense
  • Comunicación externa coordinada
```

---

### Criterios de cierre de incidente

Un incidente se puede cerrar solo cuando están documentados:

1. **Causa raíz** — qué pasó y por qué
2. **Scope del impacto** — qué datos, cuántos registros, quién tuvo acceso
3. **Acciones de contención** — qué se hizo y cuándo
4. **Remediación** — qué cambio permanente se implementó para evitar la recurrencia
5. **Lecciones aprendidas** — si aplica un ajuste de regla o un control nuevo

---

## 3. KPIs del área

### Principio de separación

Los KPIs se dividen en dos categorías: **métricas de salud** (reflejan si el programa está funcionando) y **vanity metrics** (parecen métricas pero no dicen nada sobre el riesgo real).

---

### Métricas de salud

Estas son las que importan. Cada una tiene un target y una dirección esperada.

---

**MTTD — Mean Time to Detect**  
*Tiempo promedio entre que ocurre un evento y se genera la alerta.*

```
MTTD = promedio(timestamp_alerta - timestamp_evento)
```

Target: < 5 minutos para Critical, < 30 minutos para High  
Dirección esperada: ↓ (reducir)  
Por qué importa: una brecha que se detecta en horas ya tuvo tiempo de propagarse.

---

**MTTR — Mean Time to Respond**  
*Tiempo promedio entre que se genera la alerta y se ejecuta la primera acción de contención.*

```
MTTR = promedio(timestamp_contención - timestamp_alerta)
```

Target: < 15 minutos para Critical (automatizado), < 1 hora para High  
Dirección esperada: ↓ (reducir)  
Por qué importa: mide la velocidad real de respuesta, no la de detección.

---

**Tasa de falsos positivos por tipo de alerta**  
*Porcentaje de alertas que resultaron ser ruido.*

```
FP rate = (alertas cerradas como falso positivo / total alertas) × 100
```

Target: < 15% por tipo de alerta. Si un tipo supera el 30%, la regla necesita ajuste.  
Dirección esperada: ↓ (reducir)  
Por qué importa: un programa con 80% de falsos positivos produce fatiga de alertas — los analistas dejan de investigar.

---

**Cobertura de activos sensibles**  
*Porcentaje de activos clasificados como Confidencial o Restringido que tienen una política DLP activa.*

```
Cobertura = (activos con política DLP / total activos clasificados C/R) × 100
```

Target: > 90%  
Dirección esperada: ↑ (aumentar)  
Por qué importa: sin cobertura, el programa es ciego. Esta métrica revela los gaps.

---

**% de incidentes Critical con contención automatizada**  
*De todos los incidentes Critical, cuántos tuvieron una acción de contención ejecutada sin intervención humana.*

```
Auto-contención = (Critical con contención automática / total Critical) × 100
```

Target: > 70%  
Dirección esperada: ↑ (aumentar)  
Por qué importa: la automatización es la única forma de escalar la respuesta sin crecer el equipo.

---

**Tiempo de exposición promedio (TEP)**  
*Cuánto tiempo estuvo el dato expuesto antes de ser contenido.*

```
TEP = promedio(timestamp_contención - timestamp_evento_original)
```

Target: < 30 minutos para datos Restringidos  
Dirección esperada: ↓ (reducir)  
Por qué importa: combina MTTD + MTTR en una sola métrica orientada al riesgo real para el dato.

---

**Recurrencia de incidentes por usuario**  
*Porcentaje de incidentes generados por usuarios que ya tuvieron un incidente previo en los últimos 90 días.*

```
Recurrencia = (incidentes de usuarios con historial / total incidentes) × 100
```

Target: < 10%  
Dirección esperada: ↓ (reducir)  
Por qué importa: la recurrencia indica que el proceso de remediación (capacitación, controles) no está funcionando.

---

### Vanity metrics — qué NO reportar como éxito

Estas métricas parecen positivas pero no reflejan si el programa está reduciendo el riesgo real.

| Métrica | Por qué es vanity |
|---|---|
| **Total de alertas generadas** | Más alertas no es mejor seguridad. Puede indicar más ruido. |
| **Cantidad de políticas DLP creadas** | Una política mal calibrada es peor que ninguna (produce FP o deja pasar cosas). |
| **% de empleados capacitados en seguridad** | No correlaciona con reducción de incidentes si la capacitación es un checkbox. |
| **Cantidad de incidentes cerrados en el mes** | Cerrar más incidentes puede ser señal de más ruido, no de mejor gestión. |
| **Uptime del sistema de alertas** | El sistema puede estar 100% activo y generar 90% de falsos positivos. |

---

### Dashboard recomendado (revisión semanal)

```
┌─────────────────────────────────────────────────────────────┐
│  DLP Health Dashboard — semana del [fecha]                  │
├──────────────┬──────────────┬──────────────┬───────────────┤
│  MTTD        │  MTTR        │  FP Rate     │  Cobertura    │
│  Critical    │  Critical    │  (semana)    │  activos C/R  │
│  3.2 min ↓   │  11 min ↓    │  12% ↓       │  87% ↑        │
├──────────────┴──────────────┴──────────────┴───────────────┤
│  Incidentes esta semana                                     │
│  Critical: 4  │  High: 12  │  Medium: 31  │  Low: 45       │
├─────────────────────────────────────────────────────────────┤
│  Top alert types (por volumen)                              │
│  1. BigQuery export público (8)                             │
│  2. Descarga masiva fuera de horario (7)                    │
│  3. Gmail reenvío externo (6)                               │
├─────────────────────────────────────────────────────────────┤
│  Usuarios con 2+ incidentes en 90 días: 3  ← acción requerida│
└─────────────────────────────────────────────────────────────┘
```
