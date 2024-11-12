import sys
import os
import shutil
import subprocess
import traceback
from datetime import datetime
from pathlib import Path
from collections import Counter
import pandas as pd
import matplotlib.pyplot as plt

from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QLabel, QLineEdit,
    QTextEdit, QVBoxLayout, QHBoxLayout, QFileDialog, QProgressBar,
    QComboBox, QMessageBox
)
from PyQt5.QtCore import Qt, QObject, pyqtSignal, QThread, QMutex, QWaitCondition

# Import Scapy
from scapy.all import rdpcap, TCP, UDP, IP

# ----------------- Localization Dictionary ----------------- #

translations = {
    'en': {
        'title': "PCAP Analyzer Report",
        'pcap_file': "PCAP File:",
        'browse': "Browse",
        'output_dir': "Output Directory:",
        'start_analysis': "Start Analysis",
        'log': "Log:",
        'summary': "Summary:",
        'language': "Language:",
        'invalid_pcap': "Invalid pcap file.",
        'invalid_output': "Invalid output directory.",
        'select_pcap': "Please select a valid pcap file.",
        'processing': "Processing {file}...",
        'generating_summary': "Generating summary...",
        'generating_html_report': "Generating HTML report...",
        'analysis_completed': "Analysis completed in {time:.2f} seconds.",
        'error_occurred': "An error occurred: {error}",
        'complete_report': "Complete HTML report generated at {path}",
        'open_report': "Open Report",
        'export_csv': "Export CSV",
        'pause': "Pause",
        'resume': "Resume",
        'cancel': "Cancel",
        'processing_paused': "Processing paused.",
        'processing_resumed': "Processing resumed.",
        'processing_cancelled': "Processing cancelled.",
        'export_success': "CSV exported successfully.",
        'export_failure': "Failed to export CSV.",
        'open_report_success': "Report opened successfully.",
        'open_report_failure': "Failed to open report.",
        'language_changed': "Language changed.",
        'error_occurred_summary': "An error occurred during processing. Please check the log for details.",
        'export_button': "Export CSV",
        'open_report_button': "Open Report",
        # Report Legends
        'report_title': "PCAP Analysis Report",
        'report_summary': "Summary",
        'total_packets': "Total Packets",
        'protocol_distribution': "Protocol Distribution",
        'top_talkers': "Top Talkers",
        'top_conversations': "Top Conversations",
        'source_ports': "Top Source Ports",
        'destination_ports': "Top Destination Ports",
        'filters': "Filters",
        'queries': "Queries",
        'source_ip': "Source IP",
        'destination_ip': "Destination IP",
        'protocol': "Protocol",
        'apply_filter': "Apply Filter",
        'clear_filter': "Clear Filter",
        'filtered_packets': "Filtered Packets",
        'filter_results': "Filter Results",
        'charts': "Charts",
        'packet_statistics': "Packet Statistics",
    },
    'es': {
        'title': "Reporte del Analizador de PCAP",
        'pcap_file': "Archivo PCAP:",
        'browse': "Buscar",
        'output_dir': "Directorio de Salida:",
        'start_analysis': "Iniciar Análisis",
        'log': "Registro:",
        'summary': "Resumen:",
        'language': "Idioma:",
        'invalid_pcap': "Archivo pcap inválido.",
        'invalid_output': "Directorio de salida inválido.",
        'select_pcap': "Por favor, seleccione un archivo pcap válido.",
        'processing': "Procesando {file}...",
        'generating_summary': "Generando resumen...",
        'generating_html_report': "Generando reporte HTML...",
        'analysis_completed': "Análisis completado en {time:.2f} segundos.",
        'error_occurred': "Ocurrió un error: {error}",
        'complete_report': "Reporte HTML completo generado en {path}",
        'open_report': "Abrir Reporte",
        'export_csv': "Exportar CSV",
        'pause': "Pausar",
        'resume': "Reanudar",
        'cancel': "Cancelar",
        'processing_paused': "Procesamiento pausado.",
        'processing_resumed': "Procesamiento reanudado.",
        'processing_cancelled': "Procesamiento cancelado.",
        'export_success': "CSV exportado exitosamente.",
        'export_failure': "Error al exportar CSV.",
        'open_report_success': "Reporte abierto exitosamente.",
        'open_report_failure': "Error al abrir el reporte.",
        'language_changed': "Idioma cambiado.",
        'error_occurred_summary': "Ocurrió un error durante el procesamiento. Por favor, revise el registro para más detalles.",
        'export_button': "Exportar CSV",
        'open_report_button': "Abrir Reporte",
        # Report Legends
        'report_title': "Reporte de Análisis de PCAP",
        'report_summary': "Resumen",
        'total_packets': "Total de Paquetes",
        'protocol_distribution': "Distribución de Protocolos",
        'top_talkers': "Principales Conversadores",
        'top_conversations': "Principales Conversaciones",
        'source_ports': "Principales Puertos Fuente",
        'destination_ports': "Principales Puertos Destino",
        'filters': "Filtros",
        'queries': "Consultas",
        'source_ip': "IP Fuente",
        'destination_ip': "IP Destino",
        'protocol': "Protocolo",
        'apply_filter': "Aplicar Filtro",
        'clear_filter': "Limpiar Filtro",
        'filtered_packets': "Paquetes Filtrados",
        'filter_results': "Resultados del Filtro",
        'charts': "Gráficos",
        'packet_statistics': "Estadísticas de Paquetes",
    }
}

# ----------------- Processing Worker ----------------- #

class PCAPAnalyzer(QObject):
    progress = pyqtSignal(int)          # Signal to update progress bar
    log = pyqtSignal(str)               # Signal to append log messages
    finished = pyqtSignal(float)        # Signal when processing is done
    error = pyqtSignal(str)             # Signal to emit errors

    def __init__(self, pcap_file, output_folder, lang='en'):
        super().__init__()
        self.pcap_file = pcap_file
        self.output_folder = output_folder
        self.lang = lang
        self.t = translations[self.lang]
        self._pause = False
        self._cancel = False
        self.mutex = QMutex()
        self.condition = QWaitCondition()
        self.filtered_packets = []  # To store packets after filtering

    def get_translation(self, key):
        """Helper method to fetch translations with fallback."""
        return self.t.get(key, f"[{key}]")

    def run(self):
        start_time = datetime.now()
        try:
            # Step 1: Create Report Subfolder
            report_subfolder_name = f"PCAP_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.report_folder = os.path.join(self.output_folder, report_subfolder_name)
            os.makedirs(self.report_folder, exist_ok=True)
            self.log.emit(f"<span style='color:blue;'>Report folder created at {self.report_folder}</span>")
            self.progress.emit(5)

            # Step 2: Validate PCAP File
            pcap_basename = os.path.basename(self.pcap_file)
            self.log.emit(f"<span style='color:blue;'>{self.get_translation('processing').format(file=pcap_basename)}</span>")
            if not os.path.isfile(self.pcap_file):
                raise FileNotFoundError(self.get_translation('invalid_pcap'))
            self.progress.emit(10)

            # Step 3: Load PCAP File
            self.log.emit(f"<span style='color:blue;'>Loading PCAP file...</span>")
            try:
                packets = rdpcap(self.pcap_file)
                self.log.emit(f"<span style='color:green;'>[Success]</span> Loaded {len(packets)} packets.")
            except Exception as e:
                raise Exception(f"Failed to read pcap file: {e}")
            self.progress.emit(20)

            # Step 4: Analyze Packets
            self.log.emit(f"<span style='color:blue;'>Analyzing packets...</span>")
            self.analyze_packets(packets)
            self.progress.emit(50)

            # Step 5: Generate Charts
            self.log.emit(f"<span style='color:blue;'>Generating charts...</span>")
            self.generate_charts()
            self.progress.emit(75)

            # Step 6: Generate HTML Report
            self.log.emit(f"<span style='color:blue;'>{self.get_translation('generating_html_report')}</span>")
            self.generate_html_report(elapsed_time=(datetime.now() - start_time).total_seconds())
            self.progress.emit(100)

            # Finalize
            end_time = datetime.now()
            elapsed_time = (end_time - start_time).total_seconds()
            self.log.emit(f"<span style='color:green;'>{self.get_translation('analysis_completed').format(time=elapsed_time)}</span>")
            self.finished.emit(elapsed_time)

        except Exception as e:
            error_message = self.get_translation('error_occurred').format(error=str(e))
            self.error.emit(f"<span style='color:red;'>{error_message}</span>\n{traceback.format_exc()}")

    def pause(self):
        self.mutex.lock()
        self._pause = True
        self.mutex.unlock()

    def resume(self):
        self.mutex.lock()
        self._pause = False
        self.condition.wakeAll()
        self.mutex.unlock()

    def cancel(self):
        self.mutex.lock()
        self._cancel = True
        self.condition.wakeAll()
        self.mutex.unlock()

    def check_pause_cancel(self):
        """Checks if the process should pause or cancel."""
        self.mutex.lock()
        if self._cancel:
            self.mutex.unlock()
            raise Exception(self.get_translation('processing_cancelled'))
        while self._pause:
            self.log.emit(f"<span style='color:yellow;'>{self.get_translation('processing_paused')}</span>")
            self.condition.wait(self.mutex)
            if self._cancel:
                self.mutex.unlock()
                raise Exception(self.get_translation('processing_cancelled'))
        self.mutex.unlock()

    # ----------------- Analysis Functions ----------------- #

    def analyze_packets(self, packets):
        """Analyze packets to gather statistics."""
        try:
            total_packets = len(packets)
            protocol_counter = Counter()
            src_ip_counter = Counter()
            dst_ip_counter = Counter()
            src_port_counter = Counter()
            dst_port_counter = Counter()
            conversations = Counter()

            for idx, packet in enumerate(packets):
                self.check_pause_cancel()

                if IP in packet:
                    ip_layer = packet[IP]
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst

                    src_ip_counter[src_ip] += 1
                    dst_ip_counter[dst_ip] += 1

                    if TCP in packet:
                        protocol = 'TCP'
                        sport = packet[TCP].sport
                        dport = packet[TCP].dport
                    elif UDP in packet:
                        protocol = 'UDP'
                        sport = packet[UDP].sport
                        dport = packet[UDP].dport
                    else:
                        protocol = ip_layer.proto
                        sport = 'N/A'
                        dport = 'N/A'

                    protocol_counter[protocol] += 1

                    if sport != 'N/A':
                        src_port_counter[sport] += 1
                    if dport != 'N/A':
                        dst_port_counter[dport] += 1

                    # Define conversation as (src_ip, dst_ip, protocol, sport, dport)
                    conversation = (src_ip, dst_ip, protocol, sport, dport)
                    conversations[conversation] += 1

                # Update progress every 1000 packets
                if idx % 1000 == 0 and idx != 0:
                    progress = int((idx / total_packets) * 50)  # Up to 50%
                    self.progress.emit(progress)

            # Store statistics
            self.statistics = {
                'total_packets': total_packets,
                'protocol_distribution': protocol_counter,
                'top_talkers_src': src_ip_counter.most_common(10),
                'top_talkers_dst': dst_ip_counter.most_common(10),
                'top_source_ports': src_port_counter.most_common(10),
                'top_destination_ports': dst_port_counter.most_common(10),
                'top_conversations': conversations.most_common(10)
            }

            # Generate CSV summary
            self.generate_csv_summary()

        except Exception as e:
            raise Exception(f"Error during packet analysis: {e}")

    def generate_csv_summary(self):
        """Generate a CSV summary of the analysis."""
        try:
            csv_path = os.path.join(self.report_folder, 'pcap_analysis_summary.csv')
            data = {
                'Total Packets': [self.statistics['total_packets']],
                'Top Source IPs': [', '.join([f"{ip} ({count})" for ip, count in self.statistics['top_talkers_src']])],
                'Top Destination IPs': [', '.join([f"{ip} ({count})" for ip, count in self.statistics['top_talkers_dst']])],
                'Top Source Ports': [', '.join([f"{port} ({count})" for port, count in self.statistics['top_source_ports']])],
                'Top Destination Ports': [', '.join([f"{port} ({count})" for port, count in self.statistics['top_destination_ports']])],
                'Top Conversations': [', '.join([f"{src} → {dst} ({proto}) [{sport}→{dport}] ({count})" for (src, dst, proto, sport, dport), count in self.statistics['top_conversations']])]
            }
            df = pd.DataFrame(data)
            df.to_csv(csv_path, index=False)
            self.log.emit(f"<span style='color:green;'>CSV summary generated at {csv_path}</span>")
        except Exception as e:
            raise Exception(f"Error during CSV summary generation: {e}")

    def generate_charts(self):
        """Generate charts based on the gathered statistics."""
        try:
            stats = self.statistics

            # Protocol Distribution Pie Chart
            protocols = list(stats['protocol_distribution'].keys())
            counts = list(stats['protocol_distribution'].values())
            plt.figure(figsize=(8,8))
            plt.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=140, colors=plt.cm.tab20.colors)
            plt.title('Protocol Distribution')
            plt.tight_layout()
            protocol_chart_path = os.path.join(self.report_folder, 'protocol_distribution.png')
            plt.savefig(protocol_chart_path)
            plt.close()

            # Top Source IPs Bar Chart
            users, user_counts = zip(*stats['top_talkers_src']) if stats['top_talkers_src'] else ([], [])
            plt.figure(figsize=(10,6))
            plt.bar(users, user_counts, color=plt.cm.Paired.colors)
            plt.xlabel('Source IP')
            plt.ylabel('Number of Packets')
            plt.title('Top Source IPs by Packet Count')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            top_src_chart_path = os.path.join(self.report_folder, 'top_source_ips.png')
            plt.savefig(top_src_chart_path)
            plt.close()

            # Top Destination IPs Bar Chart
            dst_users, dst_user_counts = zip(*stats['top_talkers_dst']) if stats['top_talkers_dst'] else ([], [])
            plt.figure(figsize=(10,6))
            plt.bar(dst_users, dst_user_counts, color=plt.cm.Paired.colors)
            plt.xlabel('Destination IP')
            plt.ylabel('Number of Packets')
            plt.title('Top Destination IPs by Packet Count')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            top_dst_chart_path = os.path.join(self.report_folder, 'top_destination_ips.png')
            plt.savefig(top_dst_chart_path)
            plt.close()

            # Top Source Ports Bar Chart
            src_ports, src_port_counts = zip(*stats['top_source_ports']) if stats['top_source_ports'] else ([], [])
            plt.figure(figsize=(10,6))
            plt.bar([str(port) for port in src_ports], src_port_counts, color=plt.cm.Paired.colors)
            plt.xlabel('Source Port')
            plt.ylabel('Number of Packets')
            plt.title('Top Source Ports by Packet Count')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            top_src_port_chart_path = os.path.join(self.report_folder, 'top_source_ports.png')
            plt.savefig(top_src_port_chart_path)
            plt.close()

            # Top Destination Ports Bar Chart
            dst_ports, dst_port_counts = zip(*stats['top_destination_ports']) if stats['top_destination_ports'] else ([], [])
            plt.figure(figsize=(10,6))
            plt.bar([str(port) for port in dst_ports], dst_port_counts, color=plt.cm.Paired.colors)
            plt.xlabel('Destination Port')
            plt.ylabel('Number of Packets')
            plt.title('Top Destination Ports by Packet Count')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            top_dst_port_chart_path = os.path.join(self.report_folder, 'top_destination_ports.png')
            plt.savefig(top_dst_port_chart_path)
            plt.close()

            # Top Conversations Bar Chart
            conversations, convo_counts = zip(*stats['top_conversations']) if stats['top_conversations'] else ([], [])
            convo_labels = [f"{c[0]} → {c[1]} ({c[2]}) [{c[3]}→{c[4]}]" for c in conversations]
            plt.figure(figsize=(12,7))
            plt.bar(convo_labels, convo_counts, color=plt.cm.Paired.colors)
            plt.xlabel('Conversations')
            plt.ylabel('Number of Packets')
            plt.title('Top Conversations by Packet Count')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            top_convo_chart_path = os.path.join(self.report_folder, 'top_conversations.png')
            plt.savefig(top_convo_chart_path)
            plt.close()

            # Store chart paths
            self.chart_paths = {
                'protocol_distribution': 'protocol_distribution.png',
                'top_source_ips': 'top_source_ips.png',
                'top_destination_ips': 'top_destination_ips.png',
                'top_source_ports': 'top_source_ports.png',
                'top_destination_ports': 'top_destination_ports.png',
                'top_conversations': 'top_conversations.png'
            }

        except Exception as e:
            raise Exception(f"Error during chart generation: {e}")

    def generate_html_report(self, elapsed_time):
        """Generate a descriptive HTML report."""
        try:
            report_path = os.path.join(self.report_folder, 'pcap_analysis_report.html')
            stats = self.statistics

            with open(report_path, 'w') as f:
                f.write(f"""
                <html>
                <head>
                    <title>{self.get_translation('report_title')}</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f0f2f5; }}
                        h1 {{ text-align: center; color: #2c3e50; }}
                        h2 {{ color: #34495e; }}
                        h3 {{ color: #34495e; }}
                        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                        th {{ background-color: #2980b9; color: white; }}
                        tr:nth-child(even) {{ background-color: #ecf0f1; }}
                        .chart {{ text-align: center; margin-bottom: 40px; }}
                        .filter-section {{
                            background-color: #ecf0f1;
                            padding: 15px;
                            border-radius: 5px;
                            margin-bottom: 20px;
                        }}
                        .filter-section input, .filter-section select {{
                            margin-right: 10px;
                            padding: 5px;
                        }}
                        .filter-section button {{
                            padding: 5px 10px;
                            background-color: #2980b9;
                            color: white;
                            border: none;
                            border-radius: 3px;
                            cursor: pointer;
                        }}
                        .filter-section button:hover {{
                            background-color: #3498db;
                        }}
                        .summary-box {{
                            background-color: #3498db;
                            color: white;
                            padding: 20px;
                            border-radius: 10px;
                            margin-bottom: 30px;
                        }}
                        .summary-box p {{
                            font-size: 1.1em;
                        }}
                        /* Responsive iframe for charts */
                        .responsive-iframe {{
                            position: relative;
                            padding-bottom: 56.25%;
                            padding-top: 30px;
                            height: 0;
                            overflow: hidden;
                        }}
                        .responsive-iframe iframe, .responsive-iframe img {{
                            position: absolute;
                            top: 0;
                            left: 0;
                            width: 100%;
                            height: 100%;
                        }}
                    </style>
                    <!-- Bootstrap 5 CSS -->
                    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                    <!-- DataTables CSS -->
                    <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.13.5/css/dataTables.bootstrap5.min.css">
                    <!-- jQuery -->
                    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
                    <!-- Bootstrap 5 JS -->
                    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
                    <!-- DataTables JS -->
                    <script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.13.5/js/jquery.dataTables.min.js"></script>
                    <script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.13.5/js/dataTables.bootstrap5.min.js"></script>
                </head>
                <body>
                    <div class="container">
                        <h1>{self.get_translation('report_title')}</h1>

                        <div class="summary-box">
                            <h2>{self.get_translation('report_summary')}</h2>
                            <p><strong>{self.get_translation('total_packets')}:</strong> {stats['total_packets']}</p>
                            <p><strong>Unique Source IPs:</strong> {len(stats['top_talkers_src'])}</p>
                            <p><strong>Unique Destination IPs:</strong> {len(stats['top_talkers_dst'])}</p>
                            <p><strong>Unique Source Ports:</strong> {len(stats['top_source_ports'])}</p>
                            <p><strong>Unique Destination Ports:</strong> {len(stats['top_destination_ports'])}</p>
                            <p><strong>Analysis Time:</strong> {elapsed_time:.2f} seconds</p>
                        </div>

                        <h2>{self.get_translation('protocol_distribution')}</h2>
                        <div class="chart">
                            <img src="{self.chart_paths['protocol_distribution']}" alt="Protocol Distribution" class="img-fluid">
                        </div>

                        <h2>{self.get_translation('top_talkers')}</h2>

                        <h3>Top Source IPs</h3>
                        <div class="chart">
                            <img src="{self.chart_paths['top_source_ips']}" alt="Top Source IPs" class="img-fluid">
                        </div>

                        <h3>Top Destination IPs</h3>
                        <div class="chart">
                            <img src="{self.chart_paths['top_destination_ips']}" alt="Top Destination IPs" class="img-fluid">
                        </div>

                        <h2>{self.get_translation('source_ports')}</h2>
                        <div class="chart">
                            <img src="{self.chart_paths['top_source_ports']}" alt="Top Source Ports" class="img-fluid">
                        </div>

                        <h2>{self.get_translation('destination_ports')}</h2>
                        <div class="chart">
                            <img src="{self.chart_paths['top_destination_ports']}" alt="Top Destination Ports" class="img-fluid">
                        </div>

                        <h2>{self.get_translation('top_conversations')}</h2>
                        <div class="chart">
                            <img src="{self.chart_paths['top_conversations']}" alt="Top Conversations" class="img-fluid">
                        </div>

                        <h2>{self.get_translation('filters')}</h2>
                        <div class="filter-section">
                            <label for="source_ip">{self.get_translation('source_ip')}:</label>
                            <input type="text" id="source_ip" name="source_ip" placeholder="e.g., 192.168.1.1">

                            <label for="destination_ip">{self.get_translation('destination_ip')}:</label>
                            <input type="text" id="destination_ip" name="destination_ip" placeholder="e.g., 10.0.0.5">

                            <label for="protocol">{self.get_translation('protocol')}:</label>
                            <select id="protocol" name="protocol">
                                <option value="">All</option>
                                <option value="TCP">TCP</option>
                                <option value="UDP">UDP</option>
                                <option value="ICMP">ICMP</option>
                                <option value="Other">Other</option>
                            </select>

                            <button onclick="applyFilter()">{self.get_translation('apply_filter')}</button>
                            <button onclick="clearFilter()">{self.get_translation('clear_filter')}</button>
                        </div>

                        <h2>{self.get_translation('filter_results')}</h2>
                        <div id="filter_results">
                            <p>No filter applied.</p>
                        </div>

                        <h2>{self.get_translation('queries')}</h2>
                        <div class="filter-section">
                            <button onclick="performQuery('HTTP')">Count HTTP Requests</button>
                            <button onclick="performQuery('DNS')">Count DNS Queries</button>
                            <button onclick="performQuery('SMTP')">Count SMTP Sessions</button>
                        </div>

                        <div id="query_results">
                            <p>No query performed.</p>
                        </div>

                        <!-- DataTables Tables -->

                        <h2>Detailed Tables</h2>

                        <h3>Top Source IPs</h3>
                        <table id="top_source_ips_table" class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Source IP</th>
                                    <th>Packet Count</th>
                                </tr>
                            </thead>
                            <tbody>
                        """)

                # Populate Top Source IPs Table
                for src_ip, count in stats['top_talkers_src']:
                    f.write(f"""
                            <tr>
                                <td>{src_ip}</td>
                                <td>{count}</td>
                            </tr>
                    """)

                f.write("""
                            </tbody>
                        </table>

                        <h3>Top Destination IPs</h3>
                        <table id="top_destination_ips_table" class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Destination IP</th>
                                    <th>Packet Count</th>
                                </tr>
                            </thead>
                            <tbody>
                """)

                # Populate Top Destination IPs Table
                for dst_ip, count in stats['top_talkers_dst']:
                    f.write(f"""
                            <tr>
                                <td>{dst_ip}</td>
                                <td>{count}</td>
                            </tr>
                    """)

                f.write("""
                            </tbody>
                        </table>

                        <h3>Top Source Ports</h3>
                        <table id="top_source_ports_table" class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Source Port</th>
                                    <th>Packet Count</th>
                                </tr>
                            </thead>
                            <tbody>
                """)

                # Populate Top Source Ports Table
                for port, count in stats['top_source_ports']:
                    f.write(f"""
                            <tr>
                                <td>{port}</td>
                                <td>{count}</td>
                            </tr>
                    """)

                f.write("""
                            </tbody>
                        </table>

                        <h3>Top Destination Ports</h3>
                        <table id="top_destination_ports_table" class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Destination Port</th>
                                    <th>Packet Count</th>
                                </tr>
                            </thead>
                            <tbody>
                """)

                # Populate Top Destination Ports Table
                for port, count in stats['top_destination_ports']:
                    f.write(f"""
                            <tr>
                                <td>{port}</td>
                                <td>{count}</td>
                            </tr>
                    """)

                f.write("""
                            </tbody>
                        </table>

                        <h3>Top Conversations</h3>
                        <table id="top_conversations_table" class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Source IP</th>
                                    <th>Destination IP</th>
                                    <th>Protocol</th>
                                    <th>Source Port</th>
                                    <th>Destination Port</th>
                                    <th>Packet Count</th>
                                </tr>
                            </thead>
                            <tbody>
                """)

                # Populate Top Conversations Table
                for (src, dst, proto, sport, dport), count in stats['top_conversations']:
                    f.write(f"""
                            <tr>
                                <td>{src}</td>
                                <td>{dst}</td>
                                <td>{proto}</td>
                                <td>{sport}</td>
                                <td>{dport}</td>
                                <td>{count}</td>
                            </tr>
                    """)

                f.write("""
                            </tbody>
                        </table>

                        <script>
                            $(document).ready( function () {
                                $('#top_source_ips_table').DataTable({
                                    "paging": true,
                                    "searching": true,
                                    "info": false
                                });
                                $('#top_destination_ips_table').DataTable({
                                    "paging": true,
                                    "searching": true,
                                    "info": false
                                });
                                $('#top_source_ports_table').DataTable({
                                    "paging": true,
                                    "searching": true,
                                    "info": false
                                });
                                $('#top_destination_ports_table').DataTable({
                                    "paging": true,
                                    "searching": true,
                                    "info": false
                                });
                                $('#top_conversations_table').DataTable({
                                    "paging": true,
                                    "searching": true,
                                    "info": false
                                });
                            } );

                            function applyFilter() {
                                var src_ip = document.getElementById('source_ip').value.trim();
                                var dst_ip = document.getElementById('destination_ip').value.trim();
                                var protocol = document.getElementById('protocol').value.trim();

                                var filterText = "<p>Filters Applied:</p><ul>";
                                if(src_ip) filterText += "<li>Source IP: " + src_ip + "</li>";
                                if(dst_ip) filterText += "<li>Destination IP: " + dst_ip + "</li>";
                                if(protocol) filterText += "<li>Protocol: " + protocol + "</li>";
                                filterText += "</ul>";

                                document.getElementById('filter_results').innerHTML = filterText;
                            }

                            function clearFilter() {
                                document.getElementById('source_ip').value = "";
                                document.getElementById('destination_ip').value = "";
                                document.getElementById('protocol').value = "";
                                document.getElementById('filter_results').innerHTML = "<p>No filter applied.</p>";
                            }

                            function performQuery(queryType) {
                                // Placeholder for actual query implementation
                                var resultText = "";
                                if(queryType === 'HTTP') {
                                    // Implement HTTP request counting logic
                                    resultText = "<p>Number of HTTP Requests: [Data]</p>";
                                } else if(queryType === 'DNS') {
                                    // Implement DNS query counting logic
                                    resultText = "<p>Number of DNS Queries: [Data]</p>";
                                } else if(queryType === 'SMTP') {
                                    // Implement SMTP session counting logic
                                    resultText = "<p>Number of SMTP Sessions: [Data]</p>";
                                }
                                document.getElementById('query_results').innerHTML = resultText;
                            }
                        </script>

                    </div>
                </body>
                </html>
                """)

            self.log.emit(f"<span style='color:green;'>HTML report generated at {report_path}</span>")

        except Exception as e:
            raise Exception(f"Error during HTML report generation: {e}")

# ----------------- GUI Application ----------------- #

class PCAPAnalyzerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(translations['en']['title'])
        self.setGeometry(100, 100, 900, 700)
        self.current_lang = 'en'  # Default language
        self.t = translations[self.current_lang]
        self.worker = None
        self.thread = None
        self.report_folder = None
        self.init_ui()

    def get_translation(self, key):
        """Helper method to fetch translations with fallback."""
        return self.t.get(key, f"[{key}]")

    def init_ui(self):
        layout = QVBoxLayout()

        # Language Selection
        lang_layout = QHBoxLayout()
        self.lang_label = QLabel(self.get_translation('language'))
        self.lang_combo = QComboBox()
        self.lang_combo.addItem("English", 'en')
        self.lang_combo.addItem("Español", 'es')
        self.lang_combo.currentIndexChanged.connect(self.change_language)
        lang_layout.addWidget(self.lang_label)
        lang_layout.addWidget(self.lang_combo)
        lang_layout.addStretch()
        layout.addLayout(lang_layout)

        # PCAP File Selection
        pcap_layout = QHBoxLayout()
        self.pcap_label = QLabel(self.get_translation('pcap_file'))
        self.pcap_input = QLineEdit()
        self.pcap_browse = QPushButton(self.get_translation('browse'))
        self.pcap_browse.clicked.connect(self.browse_pcap)
        pcap_layout.addWidget(self.pcap_label)
        pcap_layout.addWidget(self.pcap_input)
        pcap_layout.addWidget(self.pcap_browse)
        layout.addLayout(pcap_layout)

        # Output Directory Selection
        output_layout = QHBoxLayout()
        self.output_label = QLabel(self.get_translation('output_dir'))
        self.output_input = QLineEdit()
        self.output_browse = QPushButton(self.get_translation('browse'))
        self.output_browse.clicked.connect(self.browse_output)
        output_layout.addWidget(self.output_label)
        output_layout.addWidget(self.output_input)
        output_layout.addWidget(self.output_browse)
        layout.addLayout(output_layout)

        # Control Buttons Layout
        control_layout = QHBoxLayout()
        self.start_button = QPushButton(self.get_translation('start_analysis'))
        self.start_button.clicked.connect(self.start_analysis)
        self.pause_button = QPushButton(self.get_translation('pause'))
        self.pause_button.setEnabled(False)
        self.pause_button.clicked.connect(self.pause_analysis)
        self.resume_button = QPushButton(self.get_translation('resume'))
        self.resume_button.setEnabled(False)
        self.resume_button.clicked.connect(self.resume_analysis)
        self.cancel_button = QPushButton(self.get_translation('cancel'))
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_analysis)
        self.export_button = QPushButton(self.get_translation('export_csv'))
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_csv)
        self.open_report_button = QPushButton(self.get_translation('open_report_button'))
        self.open_report_button.setEnabled(False)
        self.open_report_button.clicked.connect(self.open_report)
        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.pause_button)
        control_layout.addWidget(self.resume_button)
        control_layout.addWidget(self.cancel_button)
        control_layout.addWidget(self.export_button)
        control_layout.addWidget(self.open_report_button)
        layout.addLayout(control_layout)

        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        # Log Field
        self.log_field = QTextEdit()
        self.log_field.setReadOnly(True)
        layout.addWidget(QLabel(self.get_translation('log')))
        layout.addWidget(self.log_field)

        # Summary Report
        self.summary_label = QLabel(self.get_translation('summary'))
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        layout.addWidget(self.summary_label)
        layout.addWidget(self.summary_text)

        self.setLayout(layout)

    def change_language(self):
        lang_code = self.lang_combo.currentData()
        self.current_lang = lang_code
        self.t = translations[self.current_lang]
        self.update_ui_texts()

    def update_ui_texts(self):
        self.setWindowTitle(self.get_translation('title'))
        self.lang_label.setText(self.get_translation('language'))
        self.pcap_label.setText(self.get_translation('pcap_file'))
        self.pcap_browse.setText(self.get_translation('browse'))
        self.output_label.setText(self.get_translation('output_dir'))
        self.output_browse.setText(self.get_translation('browse'))
        self.start_button.setText(self.get_translation('start_analysis'))
        self.pause_button.setText(self.get_translation('pause'))
        self.resume_button.setText(self.get_translation('resume'))
        self.cancel_button.setText(self.get_translation('cancel'))
        self.export_button.setText(self.get_translation('export_button'))
        self.open_report_button.setText(self.get_translation('open_report_button'))
        self.summary_label.setText(self.get_translation('summary'))
        self.log_field.clear()
        self.summary_text.clear()
        self.append_log(f"<span style='color:green;'>{self.get_translation('language_changed')}</span>")

    def browse_pcap(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        pcap_file, _ = QFileDialog.getOpenFileName(self, "Select PCAP File", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)", options=options)
        if pcap_file:
            self.pcap_input.setText(pcap_file)

    def browse_output(self):
        dir_path = QFileDialog.getExistingDirectory(self, self.get_translation('output_dir'), os.getcwd())
        if dir_path:
            self.output_input.setText(dir_path)

    def start_analysis(self):
        pcap_file = self.pcap_input.text()
        output_dir = self.output_input.text()

        if not pcap_file or not os.path.isfile(pcap_file):
            self.append_log(f"<span style='color:red;'>{self.get_translation('invalid_pcap')}</span>")
            return

        if not output_dir or not os.path.isdir(output_dir):
            self.append_log(f"<span style='color:red;'>{self.get_translation('invalid_output')}</span>")
            return

        self.output_folder = output_dir

        # Disable UI elements
        self.start_button.setEnabled(False)
        self.pcap_browse.setEnabled(False)
        self.output_browse.setEnabled(False)
        self.lang_combo.setEnabled(False)
        self.pause_button.setEnabled(True)
        self.cancel_button.setEnabled(True)
        self.resume_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.open_report_button.setEnabled(False)

        # Clear previous logs and summary
        self.log_field.clear()
        self.summary_text.clear()
        self.progress_bar.setValue(0)

        # Setup Worker and Thread
        self.thread = QThread()
        self.worker = PCAPAnalyzer(pcap_file, output_folder=self.output_folder, lang=self.current_lang)
        self.worker.moveToThread(self.thread)

        # Connect signals
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.update_progress)
        self.worker.log.connect(self.append_log)
        self.worker.finished.connect(self.process_finished)
        self.worker.error.connect(self.process_error)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.worker.error.connect(self.thread.quit)
        self.worker.error.connect(self.worker.deleteLater)

        # Start thread
        self.thread.start()

    def pause_analysis(self):
        if self.worker:
            self.worker.pause()
            self.append_log(f"<span style='color:yellow;'>{self.get_translation('processing_paused')}</span>")
            self.pause_button.setEnabled(False)
            self.resume_button.setEnabled(True)

    def resume_analysis(self):
        if self.worker:
            self.worker.resume()
            self.append_log(f"<span style='color:yellow;'>{self.get_translation('processing_resumed')}</span>")
            self.pause_button.setEnabled(True)
            self.resume_button.setEnabled(False)

    def cancel_analysis(self):
        if self.worker:
            self.worker.cancel()
            self.append_log(f"<span style='color:red;'>{self.get_translation('processing_cancelled')}</span>")
            self.start_button.setEnabled(True)
            self.pcap_browse.setEnabled(True)
            self.output_browse.setEnabled(True)
            self.lang_combo.setEnabled(True)
            self.pause_button.setEnabled(False)
            self.resume_button.setEnabled(False)
            self.cancel_button.setEnabled(False)
            self.export_button.setEnabled(False)
            self.open_report_button.setEnabled(False)

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def append_log(self, message):
        self.log_field.append(message)

    def process_finished(self, elapsed_time):
        summary_msg = f"<span style='color:green;'>{self.get_translation('analysis_completed').format(time=elapsed_time)}</span>"
        self.summary_text.append(summary_msg)
        self.start_button.setEnabled(True)
        self.pcap_browse.setEnabled(True)
        self.output_browse.setEnabled(True)
        self.lang_combo.setEnabled(True)
        self.pause_button.setEnabled(False)
        self.resume_button.setEnabled(False)
        self.cancel_button.setEnabled(False)
        self.export_button.setEnabled(True)
        self.open_report_button.setEnabled(True)

    def process_error(self, error_message):
        self.append_log(error_message)
        self.summary_text.append(f"<span style='color:red;'>{self.get_translation('error_occurred_summary')}</span>")
        self.start_button.setEnabled(True)
        self.pcap_browse.setEnabled(True)
        self.output_browse.setEnabled(True)
        self.lang_combo.setEnabled(True)
        self.pause_button.setEnabled(False)
        self.resume_button.setEnabled(False)
        self.cancel_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.open_report_button.setEnabled(False)

    def export_csv(self):
        try:
            csv_path = os.path.join(self.worker.report_folder, 'pcap_analysis_summary.csv')
            if os.path.exists(csv_path):
                export_path, _ = QFileDialog.getSaveFileName(self, "Save CSV", os.path.expanduser("~"), "CSV Files (*.csv)")
                if export_path:
                    shutil.copy(csv_path, export_path)
                    QMessageBox.information(self, "Export CSV", self.get_translation('export_success'))
            else:
                QMessageBox.warning(self, "Export CSV", self.get_translation('export_failure'))
        except Exception as e:
            QMessageBox.warning(self, "Export CSV", f"{self.get_translation('export_failure')}\n{str(e)}")

    def open_report(self):
        try:
            html_path = os.path.join(self.worker.report_folder, 'pcap_analysis_report.html')
            if os.path.exists(html_path):
                if sys.platform.startswith("darwin"):
                    subprocess.call(["open", html_path])
                elif os.name == "nt":
                    os.startfile(html_path)
                elif os.name == "posix":
                    subprocess.call(["xdg-open", html_path])
                self.append_log(f"<span style='color:green;'>{self.get_translation('open_report_success')}</span>")
            else:
                self.append_log(f"<span style='color:red;'>{self.get_translation('open_report_failure')}</span>")
        except Exception as e:
            self.append_log(f"<span style='color:red;'>{self.get_translation('open_report_failure')}</span>\n{str(e)}")

# ----------------- Main Execution ----------------- #

def main():
    app = QApplication(sys.argv)
    gui = PCAPAnalyzerGUI()
    gui.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
