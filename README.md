# osint-tool

Recolector OSINT **modular y pasivo**: le das un dominio y devuelve un mapa de
lo que se ve públicamente de él, con hallazgos ordenados por riesgo y su
remediación. Salida en JSON (para procesar) y Markdown (para leer/reportar).

## Uso responsable

Úsalo **solo contra dominios propios o con autorización por escrito**.
La herramienta prioriza fuentes pasivas (DNS público, registros de
certificados, cabeceras de respuesta) y no realiza escaneo agresivo,
fuerza bruta ni explotación.

## Instalación

```bash
python3 -m venv .venv            # si falla: apt install python3-venv, o usa --without-pip
.venv/bin/pip install -e ".[dev]"   # con --without-pip: pip --python .venv/bin/python install -e ".[dev]"
ln -sf "$PWD/.venv/bin/osint-tool" ~/.local/bin/osint-tool
```

## Uso

Pega el dominio o la URL autorizada (se acepta esquema, puerto y ruta):

```bash
osint-tool https://ejemplo.com
osint-tool ejemplo.com -m dns,headers      # solo algunos módulos
osint-tool --list-modules
```

Imprime los hallazgos por riesgo con su remediación y guarda
`<dominio>_<timestamp>.json|md` en `~/osint-reports` (cambiable con `-o`).
Código de salida: `0` ok, `1` si todos los módulos fallaron, `2` argumentos inválidos.

## Módulos

| Módulo | Qué hace | Fuente |
|---|---|---|
| `dns` | A/AAAA/NS/MX/TXT/SOA/CAA, SPF, DMARC, DNSSEC | resolvedor DNS |
| `headers` | HSTS, CSP, cookies, versiones expuestas, redirección HTTP→HTTPS | 2 peticiones a la portada |
| `subdomains` | Subdominios y entornos internos expuestos | crt.sh (respaldo: Cert Spotter) |
| `metadata` | Autores y rutas internas en PDF/docx/xlsx/pptx | portada + ≤8 páginas, ≤10 documentos |
| `whois` | Registrante, expiración, bloqueo de transferencia, certificado TLS | RDAP + conexión TLS al 443 |

Garantías de alcance: si el objetivo redirige a otro dominio, `headers` y
`metadata` no evalúan ni descargan nada del tercero y lo reportan como
hallazgo INFO. Los reportes se guardan con permisos `0600` (directorio `0700`).

Limitaciones conocidas: la lista de subdominios depende de la
transparencia de certificados (no ve hosts sin certificado público); si el
objetivo es un subdominio (`app.ejemplo.com`) se audita ese host, y solo
`www.` se normaliza al dominio base para subdominios.

## Arquitectura

```
src/osint_tool/
  cli.py          # argumentos, orquestación, escritura de reportes
  models.py       # Finding, ModuleResult, Report, Severity
  registry.py     # registro de módulos (@register)
  target.py       # validación/normalización del dominio
  modules/        # un archivo por módulo; base.py define el contrato
  report/         # render JSON y Markdown
tests/            # pytest, sin Internet (fakes + servidores locales HTTP/TLS)
```

### Añadir un módulo

1. Crea `src/osint_tool/modules/mi_modulo.py` con una clase que herede de
   `Module`, defina `name`, `description` y `run(target) -> ModuleResult`, y
   se decore con `@register`.
2. Impórtalo en `modules/__init__.py`.
3. Mantén la lógica de análisis en funciones puras y el acceso a red detrás
   de un cliente inyectable, para probarlo sin red.

## Ciclo purple team

Cada hallazgo trae su remediación. Flujo: correr → corregir (registro,
cabecera, metadatos) → volver a correr y comprobar que el hallazgo desaparece.

## Tests

```bash
pytest
```
