# PCAP Analyzer

A network packet capture analyzer with a graphical user interface (GUI) built using **PyQt5**. Processes and analyzes PCAP/PCAPNG files to generate detailed CSV summaries, charts, and interactive HTML reports.

## Features

- **PCAP Analysis** - Reads PCAP/PCAPNG files using Scapy and extracts network statistics
- **HTML Reports** - Generates styled HTML reports with Bootstrap 5 and interactive DataTables.js tables
- **Chart Generation** - Protocol distribution pie charts, top talkers, ports, and conversations bar charts
- **CSV Export** - Summary statistics exported as CSV
- **Client-side Filtering** - Filter by source IP, destination IP, and protocol directly in the HTML report
- **Protocol Queries** - Count HTTP, DNS, and SMTP packets in the report
- **Multilingual** - English and Spanish UI with dynamic language switching
- **Threaded Processing** - Background analysis with pause/resume/cancel controls

## Project Structure

```
pcap-reportgenerator/
  pcap_report/          # Main package
    __init__.py         # Package metadata
    __main__.py         # python -m pcap_report entry point
    app.py              # Application entry point (main function)
    config.py           # Configuration constants
    i18n.py             # Translations (en/es)
    analyzer.py         # PCAPAnalyzer QThread worker
    charts.py           # Matplotlib chart generation
    report.py           # HTML report generation
    csv_export.py       # CSV summary export
    gui.py              # PyQt5 GUI window
  tests/                # Unit tests
    test_i18n.py
    test_config.py
    test_csv_export.py
    test_report.py
    test_charts.py
  requirements.txt      # Python dependencies
  pyproject.toml        # Project metadata and build config
  .gitignore
  Readme.md
```

## Installation

### Quick Install

```bash
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

pip install -r requirements.txt
```

### Editable Install (with test dependencies)

```bash
pip install -e ".[test]"
```

## Usage

### Launch the GUI

```bash
# Option 1: Direct execution
python pcap_report/app.py

# Option 2: Module execution
python -m pcap_report

# Option 3: If installed via pip (console_scripts entry point)
pcap-report
```

### Using the Application

1. **Select a PCAP File** - Click "Browse" to choose a `.pcap` or `.pcapng` file
2. **Choose Output Directory** - Select where reports will be saved
3. **Start Analysis** - Click "Start Analysis" and monitor progress
4. **Export & View** - Use "Export CSV" to save summary data and "Open Report" to view the HTML report

### Running Tests

```bash
pytest tests/ -v
```

## Dependencies

| Package    | Purpose                              |
|------------|--------------------------------------|
| PyQt5      | GUI framework                        |
| pandas     | CSV data manipulation                |
| matplotlib | Chart/graph generation               |
| scapy      | PCAP file reading and packet parsing |

## License

MIT
