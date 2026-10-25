<div align="center">

# SECURE//REPO

**Auditor de seguridad de repositorios con consola de línea de comandos y una GUI de mapa neuronal.**

Análisis estático de código · detección de secretos · inteligencia de librerías y cadena de suministro ·
mapa de la estructura del repositorio · evidencia de cumplimiento opcional

[English](README.md) · [Registro de cambios](CHANGELOG.md)

</div>

---

## Qué hace

Apuntas la herramienta a un repositorio Git (el que tienes abierto, una ruta local o una URL, también privados) y lo
audita en **modo solo lectura**: nunca ejecuta el código auditado ni instala sus dependencias.

- **Análisis estático** con 175 reglas para Python, JavaScript/TypeScript, Java/Kotlin, C#, PHP, Go, Ruby, C/C++, Rust,
  shell, Dockerfiles, Kubernetes, Terraform y pipelines de CI. Python tiene análisis sobre el árbol sintáctico con
  seguimiento de datos no confiables; JavaScript/TypeScript, un análisis de flujo de datos.
- **Secretos**: claves de nube, tokens, claves privadas, cadenas de conexión, credenciales de alta entropía y archivos
  sensibles. Siempre aparecen **ocultos** en la salida.
- **Librerías**: más de 25 formatos de manifiestos y lockfiles, consultas a OSV.dev y deps.dev, y versiones resueltas
  incluso sin lockfile. Los nombres de paquetes internos se pueden mantener fuera de la red (`--private`).
- **Reportes**: una carpeta con fecha que contiene HTML, JSON, SARIF, Markdown, CSV, SBOM CycloneDX y un manifiesto de
  integridad. Por defecto se guarda **fuera** del repositorio auditado.
- **Consola y GUI**: panel en vivo en la terminal (`--theme plain` para una versión sobria) y una aplicación web local
  con mapa neuronal que explica cada debilidad y cómo corregirla.
- **Pensado para CI**: `--fail-on`, `--baseline` (falla solo con hallazgos nuevos), `--since origin/main` (solo los
  archivos cambiados) y SARIF para el escaneo de código de GitHub.
- **Cumplimiento (opcional)**: relaciona los hallazgos con 7 marcos como **evidencia de apoyo**, nunca como
  certificación.

## Inicio rápido

```bash
git clone https://github.com/Wissen01720/Secure_Repo.git
cd Secure_Repo
./run.sh scan /ruta/al/repo        # Windows: .\run.bat scan C:\ruta\al\repo
./run.sh gui                       # la interfaz gráfica
```

El lanzador crea un entorno virtual privado la primera vez. Dentro de un repositorio Git, `./run.sh` a secas abre la
consola interactiva. Se necesita Python 3.11 o superior y Git.

```bash
secure-repo scan . --yes --plain --no-menu --baseline baseline.json --fail-on high
```

## ¿Qué tan preciso es?

Medido en código que los autores no escribieron: cuatro proyectos públicos fijados a un commit (NodeGoat, DVPWA,
Vulnerable-Flask-App y la librería limpia `requests`), con cada hallazgo revisado a mano.

| | Resultado |
|---|---|
| Precisión, hallazgos de confianza media o alta | **73 %** |
| Precisión, todos los hallazgos (incluye tests y baja confianza) | 60 % |
| Debilidades documentadas encontradas | **26 de 28 (93 %)** |

Es una muestra pequeña: tómalo como una cifra mínima de evidencia y no como una garantía. Los detalles, los fallos y
cómo reproducirlo están en [docs/analysis.md](docs/analysis.md) (en inglés).

## Documentación

La documentación completa está en inglés dentro de [docs/](docs/): instalación, guía de línea de comandos, motor de
análisis, referencia de comandos y reportes, GUI, modelo de confianza y límites, solución de problemas, desarrollo y
publicación de versiones.

## Reglas de uso

> **Audita solo repositorios que sean tuyos o para los que tengas permiso explícito y por escrito.**

- Nunca ejecuta el código auditado, no instala sus dependencias y no explota ningún hallazgo.
- Pide **confirmar tu autorización** antes de cada análisis (`--yes` la confirma en automatización).
- Los secretos detectados se **ocultan** en la terminal, la GUI y todos los reportes.
- Git se ejecuta endurecido: hooks desactivados, transporte `ext::` bloqueado, clones superficiales.

Usar la herramienta para robar información o con fines maliciosos está prohibido por la [licencia](LICENSE).

## Licencia

Copyright © 2026 **Wissen01720**. Todos los derechos reservados.

Secure Repo se distribuye bajo la **Secure Repo Ethical Source-Available License**: puedes usarlo, estudiarlo y usar
sus reportes (también dentro de tu empresa) para trabajo de seguridad lícito y autorizado. **No** puedes usarlo para
acceder a código sin permiso, robar o hacer mal uso de la información que encuentra, atacar sistemas, quitar la
atribución, atribuirte la autoría, venderlo ni publicar versiones modificadas sin permiso. Lee el texto completo en
[LICENSE](LICENSE) (en inglés). Es *source-available*, no open source: si tu organización exige una licencia aprobada
por la OSI, contacta al autor.
