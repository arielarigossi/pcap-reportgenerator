"""Localization support for English and Spanish."""

LANGUAGES = {"en": "English", "es": "Español"}

_FILTER_HELP_EN = """Display filters select which packets are shown in every tab.

Protocols:  tcp  udp  icmp  arp  ipv6  dns  http  tls  ssh ...
Fields:     ip.src  ip.dst  ip.addr (host)  eth.addr  port  srcport  dstport
            tcp.port  udp.port  tcp.flags  proto  len  frame.number  time  ttl  info
Operators:  ==  !=  >  <  >=  <=  contains  matches (regex)
Logic:      and (&&)   or (||)   not (!)   ( ... )

Examples:
  ip.addr == 192.168.1.10
  ip.src == 10.0.0.0/8 and tcp.port == 443
  dns or icmp
  port 53
  tcp.flags contains R
  len > 1000 and not tls
  info contains "example.com"

Tip: double-click a row in Conversations, Endpoints, Ports or
Protocols (or right-click any packet) to filter by it."""

_FILTER_HELP_ES = """Los filtros de visualización seleccionan qué paquetes se muestran en todas las pestañas.

Protocolos: tcp  udp  icmp  arp  ipv6  dns  http  tls  ssh ...
Campos:     ip.src  ip.dst  ip.addr (host)  eth.addr  port  srcport  dstport
            tcp.port  udp.port  tcp.flags  proto  len  frame.number  time  ttl  info
Operadores: ==  !=  >  <  >=  <=  contains  matches (regex)
Lógica:     and (&&)   or (||)   not (!)   ( ... )

Ejemplos:
  ip.addr == 192.168.1.10
  ip.src == 10.0.0.0/8 and tcp.port == 443
  dns or icmp
  port 53
  tcp.flags contains R
  len > 1000 and not tls
  info contains "example.com"

Consejo: haga doble clic en una fila de Conversaciones, Extremos, Puertos o
Protocolos (o clic derecho en cualquier paquete) para filtrar por ella."""

TRANSLATIONS = {
    "en": {
        # -- application ---------------------------------------------------- #
        "title": "PCAP Analyzer",
        "ready": "Open a capture file to begin (File → Open or drag & drop).",
        "about": "About",
        "about_text": "PCAP Analyzer {version}\n\nNetwork capture analysis with "
                      "display filters, statistics and HTML/CSV reports.",
        "language": "Language",
        "language_changed": "Language changed.",
        "error": "Error",
        "menu_file": "&File",
        "menu_capture": "&Capture",
        "menu_report": "&Report",
        "menu_help": "&Help",
        "open_capture": "Open Capture...",
        "capture_files": "Capture files",
        "all_files": "All files",
        "save_filtered_pcap": "Save Displayed Packets as PCAP...",
        "export_packets_csv": "Export Displayed Packets as CSV...",
        "export_conversations_csv": "Export Conversations as CSV...",
        "quit": "Quit",
        "pause": "Pause",
        "resume": "Resume",
        "cancel": "Cancel",
        "generate_report": "Generate Report...",
        "open_report": "Open Report",
        "output_dir": "Output Directory",
        "pcap_file": "PCAP File:",
        "capture_file": "Capture File",
        # -- tabs ------------------------------------------------------------ #
        "tab_overview": "Overview",
        "tab_packets": "Packets",
        "tab_conversations": "Conversations",
        "tab_endpoints": "Endpoints",
        "tab_ports": "Ports",
        "tab_protocols": "Protocols",
        "tab_charts": "Charts",
        "tab_log": "Log",
        "overview_hint": "No capture loaded yet. Open a .pcap / .pcapng file to see its statistics.",
        "quick_search": "Quick search...",
        "rows_count": "{count} rows",
        "copy_rows": "Copy selected rows",
        "clear_log": "Clear Log",
        "chart": "Chart",
        "decode_error": "Could not decode packet",
        "frame_summary": "Frame {number}: {length} bytes",
        # -- filtering ------------------------------------------------------- #
        "display_filter": "Display filter",
        "filter_placeholder": "e.g. ip.addr == 10.0.0.1 and tcp.port == 443",
        "apply_filter": "Apply",
        "clear_filter": "Clear",
        "invalid_filter": "Invalid filter",
        "filter_help_title": "Display Filter Syntax",
        "filter_help": _FILTER_HELP_EN,
        "displayed_count": "Displayed: {shown} of {total}",
        "filter_applied": "Filter “{filter}”: {shown} of {total} packets.",
        "filter_conversation": "Filter conversation",
        "filter_address": "Filter address",
        "filter_address_a": "Filter address A",
        "filter_address_b": "Filter address B",
        "filter_as_source": "Filter as source",
        "filter_as_destination": "Filter as destination",
        "filter_port": "Filter port",
        "filter_protocol": "Filter protocol",
        "filter_source": "Filter source",
        "filter_destination": "Filter destination",
        "filter_between": "Filter traffic between hosts",
        # -- processing ------------------------------------------------------ #
        "invalid_pcap": "Invalid pcap file.",
        "processing": "Processing {file}...",
        "loaded_packets": "Loaded {count} packets.",
        "processing_paused": "Processing paused.",
        "processing_resumed": "Processing resumed.",
        "processing_cancelled": "Processing cancelled.",
        "error_occurred": "An error occurred: {error}",
        "error_occurred_summary": "An error occurred during processing. Please check the log for details.",
        "generating_report": "Generating report...",
        "generating_charts": "Generating charts...",
        "generating_summary": "Generating summary...",
        "generating_html_report": "Generating HTML report...",
        "complete_report": "Complete HTML report generated at {path}",
        "report_ready_open": "The report was generated. Open it now?",
        "open_report_success": "Report opened successfully.",
        "open_report_failure": "Failed to open report.",
        "export_success_path": "Exported to {path}",
        "export_failure": "Export failed.",
        # -- statistics / columns -------------------------------------------- #
        "no": "No.",
        "time": "Time",
        "source": "Source",
        "destination": "Destination",
        "protocol": "Protocol",
        "length": "Length",
        "info": "Info",
        "address": "Address",
        "address_a": "Address A",
        "port_a": "Port A",
        "address_b": "Address B",
        "port_b": "Port B",
        "port": "Port",
        "service": "Service",
        "packets": "Packets",
        "bytes": "Bytes",
        "packets_a_to_b": "Packets A→B",
        "packets_b_to_a": "Packets B→A",
        "bytes_a_to_b": "Bytes A→B",
        "bytes_b_to_a": "Bytes B→A",
        "packets_sent": "Packets Sent",
        "packets_received": "Packets Received",
        "bytes_sent": "Bytes Sent",
        "bytes_received": "Bytes Received",
        "as_source": "As Source",
        "as_destination": "As Destination",
        "percent_packets": "% Packets",
        "duration": "Duration",
        "total_packets": "Total Packets",
        "displayed_packets": "Displayed / Total Packets",
        "total_bytes": "Total Bytes",
        "avg_packet_size": "Average Packet Size",
        "packets_per_second": "Packets per Second",
        "throughput": "Average Throughput",
        "unique_src_ips": "Unique Source Addresses",
        "unique_dst_ips": "Unique Destination Addresses",
        "conversations": "Conversations",
        "endpoints": "Endpoints",
        "first_packet": "First Packet",
        "last_packet": "Last Packet",
        "transport_protocols": "Transport Protocols",
        "application_protocols": "Application Protocols",
        "source_ip": "Source IP",
        "destination_ip": "Destination IP",
        "source_port": "Source Port",
        "destination_port": "Destination Port",
        # -- charts ---------------------------------------------------------- #
        "protocol_distribution": "Protocol Distribution",
        "top_source_ips": "Top Source IPs",
        "top_destination_ips": "Top Destination IPs",
        "source_ports": "Top Source Ports",
        "destination_ports": "Top Destination Ports",
        "top_conversations": "Top Conversations",
        "traffic_over_time": "Traffic Over Time",
        "packet_sizes": "Packet Size Distribution",
        "packet_size_bytes": "Packet size (bytes)",
        "time_seconds": "Time since first packet (s)",
        "packets_per_interval": "Packets per {interval}",
        "no_data": "No data available",
        "other": "Other",
        # -- HTML report ----------------------------------------------------- #
        "report_title": "PCAP Analysis Report",
        "report_summary": "Summary",
        "generated_at": "Generated",
        "charts": "Charts",
        "filters": "Filters",
        "queries": "Queries",
        "all": "All",
        "filter_results": "Filter Results",
        "no_filter_applied": "No filter applied.",
        "no_matches": "No matching conversations found.",
        "matching_conversations": "matching conversation(s) found.",
        "count_packets": "Count {name} packets",
        "no_query": "No query performed.",
        "detailed_tables": "Detailed Tables",
    },
    "es": {
        # -- application ---------------------------------------------------- #
        "title": "Analizador de PCAP",
        "ready": "Abra un archivo de captura para comenzar (Archivo → Abrir o arrastrar y soltar).",
        "about": "Acerca de",
        "about_text": "Analizador de PCAP {version}\n\nAnálisis de capturas de red con "
                      "filtros de visualización, estadísticas y reportes HTML/CSV.",
        "language": "Idioma",
        "language_changed": "Idioma cambiado.",
        "error": "Error",
        "menu_file": "&Archivo",
        "menu_capture": "&Captura",
        "menu_report": "&Reporte",
        "menu_help": "A&yuda",
        "open_capture": "Abrir Captura...",
        "capture_files": "Archivos de captura",
        "all_files": "Todos los archivos",
        "save_filtered_pcap": "Guardar Paquetes Mostrados como PCAP...",
        "export_packets_csv": "Exportar Paquetes Mostrados como CSV...",
        "export_conversations_csv": "Exportar Conversaciones como CSV...",
        "quit": "Salir",
        "pause": "Pausar",
        "resume": "Reanudar",
        "cancel": "Cancelar",
        "generate_report": "Generar Reporte...",
        "open_report": "Abrir Reporte",
        "output_dir": "Directorio de Salida",
        "pcap_file": "Archivo PCAP:",
        "capture_file": "Archivo de Captura",
        # -- tabs ------------------------------------------------------------ #
        "tab_overview": "Resumen",
        "tab_packets": "Paquetes",
        "tab_conversations": "Conversaciones",
        "tab_endpoints": "Extremos",
        "tab_ports": "Puertos",
        "tab_protocols": "Protocolos",
        "tab_charts": "Gráficos",
        "tab_log": "Registro",
        "overview_hint": "Aún no se cargó ninguna captura. Abra un archivo .pcap / .pcapng para ver sus estadísticas.",
        "quick_search": "Búsqueda rápida...",
        "rows_count": "{count} filas",
        "copy_rows": "Copiar filas seleccionadas",
        "clear_log": "Limpiar Registro",
        "chart": "Gráfico",
        "decode_error": "No se pudo decodificar el paquete",
        "frame_summary": "Trama {number}: {length} bytes",
        # -- filtering ------------------------------------------------------- #
        "display_filter": "Filtro de visualización",
        "filter_placeholder": "ej. ip.addr == 10.0.0.1 and tcp.port == 443",
        "apply_filter": "Aplicar",
        "clear_filter": "Limpiar",
        "invalid_filter": "Filtro inválido",
        "filter_help_title": "Sintaxis del Filtro de Visualización",
        "filter_help": _FILTER_HELP_ES,
        "displayed_count": "Mostrados: {shown} de {total}",
        "filter_applied": "Filtro “{filter}”: {shown} de {total} paquetes.",
        "filter_conversation": "Filtrar conversación",
        "filter_address": "Filtrar dirección",
        "filter_address_a": "Filtrar dirección A",
        "filter_address_b": "Filtrar dirección B",
        "filter_as_source": "Filtrar como origen",
        "filter_as_destination": "Filtrar como destino",
        "filter_port": "Filtrar puerto",
        "filter_protocol": "Filtrar protocolo",
        "filter_source": "Filtrar origen",
        "filter_destination": "Filtrar destino",
        "filter_between": "Filtrar tráfico entre hosts",
        # -- processing ------------------------------------------------------ #
        "invalid_pcap": "Archivo pcap inválido.",
        "processing": "Procesando {file}...",
        "loaded_packets": "Se cargaron {count} paquetes.",
        "processing_paused": "Procesamiento pausado.",
        "processing_resumed": "Procesamiento reanudado.",
        "processing_cancelled": "Procesamiento cancelado.",
        "error_occurred": "Ocurrió un error: {error}",
        "error_occurred_summary": "Ocurrió un error durante el procesamiento. Por favor, revise el registro para más detalles.",
        "generating_report": "Generando reporte...",
        "generating_charts": "Generando gráficos...",
        "generating_summary": "Generando resumen...",
        "generating_html_report": "Generando reporte HTML...",
        "complete_report": "Reporte HTML completo generado en {path}",
        "report_ready_open": "El reporte fue generado. ¿Abrirlo ahora?",
        "open_report_success": "Reporte abierto exitosamente.",
        "open_report_failure": "Error al abrir el reporte.",
        "export_success_path": "Exportado a {path}",
        "export_failure": "Error al exportar.",
        # -- statistics / columns -------------------------------------------- #
        "no": "N.º",
        "time": "Tiempo",
        "source": "Origen",
        "destination": "Destino",
        "protocol": "Protocolo",
        "length": "Longitud",
        "info": "Info",
        "address": "Dirección",
        "address_a": "Dirección A",
        "port_a": "Puerto A",
        "address_b": "Dirección B",
        "port_b": "Puerto B",
        "port": "Puerto",
        "service": "Servicio",
        "packets": "Paquetes",
        "bytes": "Bytes",
        "packets_a_to_b": "Paquetes A→B",
        "packets_b_to_a": "Paquetes B→A",
        "bytes_a_to_b": "Bytes A→B",
        "bytes_b_to_a": "Bytes B→A",
        "packets_sent": "Paquetes Enviados",
        "packets_received": "Paquetes Recibidos",
        "bytes_sent": "Bytes Enviados",
        "bytes_received": "Bytes Recibidos",
        "as_source": "Como Origen",
        "as_destination": "Como Destino",
        "percent_packets": "% Paquetes",
        "duration": "Duración",
        "total_packets": "Total de Paquetes",
        "displayed_packets": "Paquetes Mostrados / Totales",
        "total_bytes": "Total de Bytes",
        "avg_packet_size": "Tamaño Promedio de Paquete",
        "packets_per_second": "Paquetes por Segundo",
        "throughput": "Rendimiento Promedio",
        "unique_src_ips": "Direcciones de Origen Únicas",
        "unique_dst_ips": "Direcciones de Destino Únicas",
        "conversations": "Conversaciones",
        "endpoints": "Extremos",
        "first_packet": "Primer Paquete",
        "last_packet": "Último Paquete",
        "transport_protocols": "Protocolos de Transporte",
        "application_protocols": "Protocolos de Aplicación",
        "source_ip": "IP Fuente",
        "destination_ip": "IP Destino",
        "source_port": "Puerto Fuente",
        "destination_port": "Puerto Destino",
        # -- charts ---------------------------------------------------------- #
        "protocol_distribution": "Distribución de Protocolos",
        "top_source_ips": "Principales IPs de Origen",
        "top_destination_ips": "Principales IPs de Destino",
        "source_ports": "Principales Puertos Fuente",
        "destination_ports": "Principales Puertos Destino",
        "top_conversations": "Principales Conversaciones",
        "traffic_over_time": "Tráfico en el Tiempo",
        "packet_sizes": "Distribución de Tamaños de Paquete",
        "packet_size_bytes": "Tamaño del paquete (bytes)",
        "time_seconds": "Tiempo desde el primer paquete (s)",
        "packets_per_interval": "Paquetes por {interval}",
        "no_data": "No hay datos disponibles",
        "other": "Otros",
        # -- HTML report ----------------------------------------------------- #
        "report_title": "Reporte de Análisis de PCAP",
        "report_summary": "Resumen",
        "generated_at": "Generado",
        "charts": "Gráficos",
        "filters": "Filtros",
        "queries": "Consultas",
        "all": "Todos",
        "filter_results": "Resultados del Filtro",
        "no_filter_applied": "No se aplicó ningún filtro.",
        "no_matches": "No se encontraron conversaciones coincidentes.",
        "matching_conversations": "conversación(es) coincidente(s).",
        "count_packets": "Contar paquetes {name}",
        "no_query": "No se realizó ninguna consulta.",
        "detailed_tables": "Tablas Detalladas",
    },
}


def get_translation(lang, key):
    """Return the translated string for a given language and key.

    Falls back to English for unknown languages and to ``[key]`` if the
    key is missing.
    """
    return TRANSLATIONS.get(lang, TRANSLATIONS["en"]).get(key, f"[{key}]")


class Translator:
    """Callable translator whose language can be switched at runtime.

    ``tr("key", **kwargs)`` returns the translated (and formatted) text.
    """

    def __init__(self, lang="en"):
        self.lang = lang if lang in TRANSLATIONS else "en"

    def set_language(self, lang):
        if lang in TRANSLATIONS:
            self.lang = lang

    def __call__(self, key, **kwargs):
        text = get_translation(self.lang, key)
        return text.format(**kwargs) if kwargs else text
