"""Tabs of the main window.

Every data tab implements ``update_stats(stats, records)`` and
``retranslate()``; tabs offering "apply as filter" actions expose a
``filter_requested(str)`` signal.
"""

from pcap_report.gui.tabs.charts import ChartsTab
from pcap_report.gui.tabs.log import LogTab
from pcap_report.gui.tabs.overview import OverviewTab
from pcap_report.gui.tabs.packets import PacketsTab
from pcap_report.gui.tabs.statistics_tabs import (
    ConversationsTab, EndpointsTab, PortsTab, ProtocolsTab,
)

__all__ = ["ChartsTab", "LogTab", "OverviewTab", "PacketsTab", "ConversationsTab",
           "EndpointsTab", "PortsTab", "ProtocolsTab"]
