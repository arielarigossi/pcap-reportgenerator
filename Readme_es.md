# PCAP Analyzer

[Read in English](Readme.md)

Analizador de capturas de red con interfaz gráfica de pestañas construida con **PyQt5**. Abra un archivo PCAP/PCAPNG, explórelo desde distintas vistas, acote todo con filtros de visualización al estilo Wireshark y exporte informes HTML/CSV, desde la GUI o desde la línea de comandos sin interfaz.

## Características

- **Vistas en pestañas** de la misma captura:
  | Pestaña | Qué muestra |
  |---------|-------------|
  | Resumen | Paquetes, bytes, duración, rendimiento, direcciones únicas, primer/último paquete |
  | Paquetes | Lista de paquetes coloreada, árbol de disección por capas y volcado hexadecimal |
  | Conversaciones | Flujos bidireccionales A ↔ B con paquetes/bytes por sentido y duración |
  | Extremos | Paquetes y bytes enviados/recibidos por dirección |
  | Puertos | Uso de puertos como origen/destino con nombre del servicio conocido |
  | Protocolos | Distribución de protocolos de transporte y de aplicación |
  | Gráficos | Gráficos interactivos (zoom/desplazamiento/guardar): torta de protocolos, tráfico en el tiempo, principales IPs, puertos, conversaciones, tamaños de paquete |
  | Registro | Registro de actividad |
- **Filtros de visualización** aplicados a *todas* las pestañas a la vez, con validación en vivo, ejemplos, historial y ayuda integrada (botón `?`):
  ```
  ip.addr == 192.168.1.10
  ip.src == 10.0.0.0/8 and tcp.port == 443
  dns or icmp
  port 53
  tcp.flags contains R
  len > 1000 and not tls
  info contains "example.com"
  proto matches "^(HTTP|TLS)$"
  ```
  Campos: `ip.src ip.dst ip.addr/host eth.src eth.dst eth.addr port srcport dstport tcp.port udp.port tcp.flags proto len frame.number time ttl info`. Operadores: `== != > < >= <= contains matches` (y `eq ne gt lt ge le`). Lógica: `and/&& or/|| not/!` y paréntesis. Un nombre de protocolo solo (`tcp`, `dns`, `http`, …) selecciona ese protocolo.
- **Filtrar desde cualquier vista**: doble clic (o clic derecho) en una conversación, extremo, puerto, protocolo o paquete para filtrar por él.
- **Exportaciones**: guarde los paquetes mostrados como PCAP o CSV y exporte las conversaciones como CSV.
- **Informes HTML**: tarjetas de resumen, gráficos, filtrado de conversaciones, consultas por protocolo y tablas con búsqueda (Bootstrap 5 + DataTables, utilizable también sin conexión). Los informes respetan el filtro activo.
- **Modo sin interfaz** para scripts e integración continua.
- **Multilingüe**: inglés y español, intercambiables en tiempo de ejecución (se recuerda entre sesiones).
- **Fluido**: la carga de capturas y la generación de informes se ejecutan en segundo plano con pausa/reanudar/cancelar y barra de progreso. Arrastre y suelte una captura sobre la ventana para abrirla.

## Instalación

```bash
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

pip install -r requirements.txt
# o bien, editable con dependencias de pruebas:
pip install -e ".[test]"
```

## Uso

```bash
# GUI
python pcap-report.py                 # desde el repositorio
python -m pcap_report                 # como módulo
pcap-report                           # tras pip install
pcap-report captura.pcapng            # abrir un archivo directamente
pcap-report --lang es                 # interfaz en español

# Informe sin interfaz
pcap-report captura.pcap --no-gui -o informes/ -f "tcp.port == 443" --lang es
```

El modo sin interfaz imprime las rutas del contenido generado en la carpeta `PCAP_Report_<fecha>/` (informe HTML, resumen CSV y gráficos PNG).

### Ejecutar las pruebas

```bash
pytest
```

Las pruebas de la GUI usan la plataforma `offscreen` de Qt, por lo que no requieren pantalla.

## Estructura del Proyecto

```
pcap-reportgenerator/
  pcap-report.py           # Lanzador desde el repositorio
  pcap_report/
    app.py                 # Punto de entrada CLI (GUI o --no-gui)
    config.py              # Constantes y filtros de ejemplo
    i18n.py                # Traducciones (en/es) y Translator
    formatting.py          # Formato legible de números, bytes y tiempos
    core/                  # Lógica independiente de Qt (con pruebas unitarias)
      models.py            #   PacketRecord, Conversation, Endpoint, ...
      parser.py            #   Lector pcap/pcapng en streaming -> PacketRecord
      protocols.py         #   Tablas de protocolos IP y puertos conocidos
      filters.py           #   Tokenizador, analizador y compilador de filtros
      statistics.py        #   Agregación CaptureStatistics
      control.py           #   Pausa/reanudar/cancelar seguro entre hilos
    reporting/             # Artefactos de salida
      charts.py            #   Constructores de figuras matplotlib (compartidos con la GUI)
      html_report.py       #   Informe HTML
      csv_export.py        #   CSV de resumen / paquetes / conversaciones
      pipeline.py          #   generate_report(): gráficos + CSV + HTML
    gui/                   # Interfaz PyQt5
      main_window.py       #   Menús, barra de herramientas, filtros, tareas
      filter_bar.py        #   Entrada de filtro con validación e historial
      workers.py           #   Envoltorio de QThread
      table_model.py       #   Modelo de tabla genérico por columnas
      tabs/                #   Un módulo por pestaña
  tests/                   # Pruebas pytest (core, informes, CLI, GUI)
```

### Notas de arquitectura

- `core` nunca importa Qt, por lo que el análisis, el filtrado y las estadísticas se pueden reutilizar y probar por separado.
- Cada pestaña implementa `update_stats(stats, records)` y `retranslate()`; la ventana principal aplica el filtro una vez, recalcula `CaptureStatistics` y lo envía a todas las pestañas. Agregar una vista consiste en escribir una clase de pestaña y registrarla en `MainWindow._build_tabs`.
- Las pestañas de tabla se declaran como una lista de `Column` más acciones opcionales de "aplicar como filtro"; el orden y la búsqueda rápida los aporta `TableTab`.
- Los gráficos usan la API orientada a objetos de matplotlib, de modo que los mismos constructores dibujan en la GUI y en los PNG del informe desde un hilo secundario.

## Dependencias

| Paquete    | Propósito                                  |
|------------|--------------------------------------------|
| PyQt5      | Framework de la GUI                        |
| matplotlib | Gráficos                                   |
| scapy      | Lectura de PCAP y disección de paquetes    |

## Licencia

MIT
