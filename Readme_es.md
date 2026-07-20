# PCAP Analyzer

Analizador de capturas de red con interfaz gráfica (GUI) construida con **PyQt5**. Procesa y analiza archivos PCAP/PCAPNG para generar resúmenes CSV, gráficos e informes HTML interactivos.

## Características

- **Análisis PCAP** - Lee archivos PCAP/PCAPNG con Scapy y extrae estadísticas de red
- **Informes HTML** - Genera informes HTML estilizados con Bootstrap 5 y tablas interactivas DataTables.js
- **Generación de Gráficos** - Gráficos de torta (distribución de protocolos) y barras (principales IPs, puertos, conversaciones)
- **Exportación CSV** - Estadísticas resumidas exportadas como CSV
- **Filtrado del lado del cliente** - Filtre por IP origen, IP destino y protocolo directamente en el informe HTML
- **Consultas de Protocolo** - Cuente paquetes HTTP, DNS y SMTP en el informe
- **Multilingüe** - Interfaz en inglés y español con cambio dinámico de idioma
- **Procesamiento en segundo plano** - Análisis concurrente con controles de pausa/reanudar/cancelar

## Estructura del Proyecto

```
pcap-reportgenerator/
  pcap_report/          # Paquete principal
    __init__.py         # Metadatos del paquete
    __main__.py         # Punto de entrada python -m pcap_report
    app.py              # Punto de entrada de la aplicación (función main)
    config.py           # Constantes de configuración
    i18n.py             # Traducciones (en/es)
    analyzer.py         # Worker PCAPAnalyzer (QThread)
    charts.py           # Generación de gráficos con Matplotlib
    report.py           # Generación de informes HTML
    csv_export.py       # Exportación de resumen CSV
    gui.py              # Ventana GUI con PyQt5
  tests/                # Tests unitarios
    test_i18n.py
    test_config.py
    test_csv_export.py
    test_report.py
    test_charts.py
  requirements.txt      # Dependencias de Python
  pyproject.toml        # Metadatos y configuración de构建
  .gitignore
  Readme.md
  Readme_es.md
```

## Instalación

### Instalación Rápida

```bash
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

pip install -r requirements.txt
```

### Instalación en Modo Desarrollo (con dependencias de test)

```bash
pip install -e ".[test]"
```

## Uso

### Iniciar la GUI

```bash
# Opción 1: Ejecución directa
python pcap_report/app.py

# Opción 2: Ejecución como módulo
python -m pcap_report

# Opción 3: Si se instaló con pip (punto de entrada console_scripts)
pcap-report
```

### Usando la Aplicación

1. **Seleccionar Archivo PCAP** - Haga clic en "Buscar" para elegir un archivo `.pcap` o `.pcapng`
2. **Elegir Directorio de Salida** - Seleccione dónde se guardarán los informes
3. **Iniciar Análisis** - Haga clic en "Iniciar Análisis" y monitoree el progreso
4. **Exportar y Ver** - Use "Exportar CSV" para guardar los datos resumidos y "Abrir Reporte" para ver el informe HTML

### Ejecutar Tests

```bash
pytest tests/ -v
```

## Dependencias

| Paquete   | Propósito                                 |
|-----------|-------------------------------------------|
| PyQt5     | Framework de GUI                          |
| pandas    | Manipulación de datos CSV                 |
| matplotlib| Generación de gráficos                    |
| scapy     | Lectura de archivos PCAP y análisis de paquetes |

## Licencia

MIT
