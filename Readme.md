# PCAP Analyzer

[Leer en Español](Readme_es.md)

A network packet capture analyzer with a tabbed **PyQt5** GUI. Open a PCAP/PCAPNG file, explore it through several views, narrow everything down with Wireshark-style display filters, and export HTML/CSV reports — from the GUI or headless from the command line.

## Features

- **Tabbed views** of the same capture:
  | Tab | What it shows |
  |-----|---------------|
  | Overview | Packets, bytes, duration, throughput, unique addresses, first/last packet |
  | Packets | Colour-coded packet list, layer-by-layer dissection tree and hex dump |
  | Conversations | Bidirectional A ↔ B flows with packets/bytes per direction and duration |
  | Endpoints | Per-address packets and bytes sent/received |
  | Ports | Port usage as source/destination with well-known service names |
  | Protocols | Transport and application protocol distribution |
  | Charts | Interactive charts (zoom/pan/save): protocol pie, traffic over time, top talkers, ports, conversations, packet sizes |
  | Log | Activity log |
- **Display filters** applied to *every* tab at once, with live validation, presets, history and built-in help (`?` button):
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
  Fields: `ip.src ip.dst ip.addr/host eth.src eth.dst eth.addr port srcport dstport tcp.port udp.port tcp.flags proto len frame.number time ttl info`. Operators: `== != > < >= <= contains matches` (and `eq ne gt lt ge le`). Logic: `and/&& or/|| not/!` and parentheses. A bare protocol name (`tcp`, `dns`, `http`, …) selects that protocol.
- **Filter from any view** — double-click (or right-click) a conversation, endpoint, port, protocol or packet to filter by it.
- **Exports** — save the displayed packets as PCAP or CSV, export conversations as CSV.
- **HTML reports** — summary cards, charts, conversation filtering, protocol queries and searchable tables (Bootstrap 5 + DataTables, still usable offline). Reports honour the active display filter.
- **Headless mode** for scripts and CI.
- **Multilingual** — English and Spanish, switchable at runtime (remembered between sessions).
- **Responsive** — capture loading and report generation run in background threads with pause/resume/cancel and a progress bar. Drag & drop a capture onto the window to open it.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

pip install -r requirements.txt
# or, editable with test dependencies:
pip install -e ".[test]"
```

## Usage

```bash
# GUI
python pcap-report.py                 # from a source checkout
python -m pcap_report                 # module execution
pcap-report                           # after pip install
pcap-report capture.pcapng            # open a file right away
pcap-report --lang es                 # Spanish interface

# Headless report (no GUI)
pcap-report capture.pcap --no-gui -o reports/ -f "tcp.port == 443" --lang en
```

Headless mode prints the paths of the generated `PCAP_Report_<timestamp>/` folder contents (HTML report, CSV summary and chart PNGs).

### Running tests

```bash
pytest
```

GUI tests run with Qt's `offscreen` platform, so no display is needed.

## Project Structure

```
pcap-reportgenerator/
  pcap-report.py           # Run-from-checkout launcher
  pcap_report/
    app.py                 # CLI entry point (GUI or --no-gui)
    config.py              # Constants and filter presets
    i18n.py                # Translations (en/es) and Translator
    formatting.py          # Human-friendly number/byte/time formatting
    core/                  # Qt-independent logic (fully unit tested)
      models.py            #   PacketRecord, Conversation, Endpoint, ...
      parser.py            #   Streaming pcap/pcapng reader -> PacketRecord
      protocols.py         #   IP protocol / well-known port tables
      filters.py           #   Display filter tokenizer, parser and compiler
      statistics.py        #   CaptureStatistics aggregation
      control.py           #   Thread-safe pause/resume/cancel (TaskControl)
    reporting/             # Output artefacts
      charts.py            #   matplotlib Figure builders (shared with the GUI)
      html_report.py       #   HTML report
      csv_export.py        #   Summary / packets / conversations CSV
      pipeline.py          #   generate_report(): charts + CSV + HTML
    gui/                   # PyQt5 interface
      main_window.py       #   Menus, toolbar, filter wiring, tasks
      filter_bar.py        #   Display filter input with validation/history
      workers.py           #   QThread worker wrapper
      table_model.py       #   Generic column-driven table model
      tabs/                #   One module per tab
  tests/                   # pytest suite (core, reporting, CLI, GUI)
```

### Architecture notes

- `core` never imports Qt, so parsing, filtering and statistics can be reused and tested on their own.
- Each tab implements `update_stats(stats, records)` and `retranslate()`; the main window applies the display filter once, recomputes `CaptureStatistics` and pushes it to every tab. Adding a view means writing one tab class and registering it in `MainWindow._build_tabs`.
- Table tabs are declared as a list of `Column`s plus optional "apply as filter" actions; sorting and quick search come from the shared `TableTab`.
- Charts are built with matplotlib's object-oriented API, so the same builders render into the GUI canvas and into report PNGs from a worker thread.

## Dependencies

| Package    | Purpose                              |
|------------|--------------------------------------|
| PyQt5      | GUI framework                        |
| matplotlib | Charts                               |
| scapy      | PCAP reading and packet dissection   |

## License

MIT
