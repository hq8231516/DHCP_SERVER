#!/usr/bin/env python3
"""DHCP IP Allocator V1.00 - select a network interface, then answer DHCP
Discover/Request packets with one fixed IP address (default 192.168.1.20).
"""
import sys
import os
import threading
import subprocess
import time
import traceback
import ctypes
from datetime import datetime

from scapy.all import *
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QComboBox, QLineEdit
)
from PyQt5.QtCore import QTimer

VERSION = "V1.00"

# ---- Global exception hook ----
def excepthook(exc_type, exc_value, exc_tb):
    msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
    try:
        ctypes.windll.user32.MessageBoxW(
            0, f"Program crashed:\n{exc_value}", "IP Address Allocator - Error", 0x10)
    except Exception:
        pass
sys.excepthook = excepthook
threading.excepthook = lambda args: excepthook(args.exc_type, args.exc_value, args.exc_traceback)

# DHCP defaults
DEFAULT_OFFERED_IP = "192.168.1.20"
LEASE_TIME = 43200  # 12 hours


def get_interface_list():
    """Return (display_name, NetworkInterface) pairs, skipping interfaces
    without an IPv4 address and the loopback address."""
    result = []
    for guid, iface in conf.ifaces.items():
        ip = iface.ip or ""
        if not ip or ip in ("127.0.0.1", "(无IP)"):
            continue
        name = iface.name or f"NIC {guid[:8]}"
        display = f"{name} ({ip})"
        result.append((display, iface))
    # Chinese Windows localizes the loopback name, so keep that check too.
    result.sort(key=lambda x: ("loopback" in x[0].lower() or "回环" in x[0], x[0]))
    return result


def get_mac_from_ipconfig(target_ip):
    """Fallback: read the MAC address of a given IPv4 address from ipconfig."""
    if not target_ip:
        return None
    status, out = subprocess.getstatusoutput("ipconfig /all")
    if status != 0:
        return None
    lines = out.split("\n")
    for i, line in enumerate(lines):
        if "IPv4" in line:
            ip = line.split(": ")[-1].split("(")[0].strip()
            if ip == target_ip:
                for j in range(i, max(-1, i - 10), -1):
                    low = lines[j].lower()
                    if "物理地址" in lines[j] or "physical address" in low:
                        return lines[j].split(": ")[-1].strip().replace("-", ":")
    return None


class DHCPApp(QWidget):
    def __init__(self):
        super().__init__()
        self.running = False
        self.lease_records = {}
        self.sniff_thread = None
        self.e = threading.Event()
        self.net_iface = None
        self.server_ip = None
        self.server_mac = None
        self.offered_ip = DEFAULT_OFFERED_IP
        self._selected_iface = None
        self._send_queue = []
        self._send_lock = threading.Lock()
        self._sender_stop = threading.Event()
        self._sender_thread = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle(f"IP Address Allocator - {VERSION}")
        self.setMinimumWidth(420)

        layout = QVBoxLayout()

        # Network interface selection
        iface_layout = QHBoxLayout()
        iface_layout.addWidget(QLabel("Interface:"))
        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(240)
        iface_list = get_interface_list()
        self._iface_map = {display: iface for display, iface in iface_list}
        self.iface_combo.addItems(list(self._iface_map.keys()))
        if iface_list:
            self.iface_combo.setCurrentIndex(0)
            self._selected_iface = iface_list[0][1]
        self.iface_combo.currentIndexChanged.connect(self._on_iface_changed)
        iface_layout.addWidget(self.iface_combo)
        iface_layout.addStretch()
        layout.addLayout(iface_layout)

        # IP address to assign
        ip_layout = QHBoxLayout()
        ip_layout.addWidget(QLabel("Assign IP:"))
        self.ip_edit = QLineEdit(DEFAULT_OFFERED_IP)
        self.ip_edit.setMinimumWidth(120)
        ip_layout.addWidget(self.ip_edit)

        ip_layout.addStretch()
        layout.addLayout(ip_layout)

        # Buttons
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start")
        self.start_btn.clicked.connect(self.start_server)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_server)
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        layout.addLayout(btn_layout)

        # Log area
        layout.addWidget(QLabel("Log:"))
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setMaximumHeight(200)
        layout.addWidget(self.log_area)

        self.setLayout(layout)

    def _on_iface_changed(self):
        display = self.iface_combo.currentText()
        self._selected_iface = self._iface_map.get(display)

    def _log(self, msg):
        """Append a timestamped message to the UI log."""
        ts = datetime.now().strftime("%H:%M:%S")
        try:
            self.log_area.append(f"[{ts}] {msg}")
            self.log_area.verticalScrollBar().setValue(self.log_area.verticalScrollBar().maximum())
        except Exception:
            pass

    def respond_to_dhcp_discover(self, pkt):
        try:
            if not (DHCP in pkt and pkt[DHCP].options and pkt[DHCP].options[0][1] == 1):
                return
            client_mac = pkt[Ether].src
            if self.server_mac and client_mac.upper() == self.server_mac.upper():
                return
            offer = (Ether(src=self.server_mac, dst=client_mac) /
                     IP(src=self.server_ip, dst=self.offered_ip) /
                     UDP(sport=67, dport=68) /
                     BOOTP(op=2, chaddr=pkt[BOOTP].chaddr, yiaddr=self.offered_ip,
                           siaddr=self.server_ip, xid=pkt[BOOTP].xid, secs=pkt[BOOTP].secs) /
                     DHCP(options=[
                         ("message-type", "offer"),
                         ("server_id", self.server_ip),
                         ("lease_time", LEASE_TIME),
                         ("subnet_mask", "255.255.255.0"),
                         ("router", self.server_ip),
                         ("end")
                     ]))
            self._queue_packet(offer)
        except Exception:
            pass

    def respond_to_dhcp_request(self, pkt):
        try:
            if not (DHCP in pkt and pkt[DHCP].options and pkt[DHCP].options[0][1] == 3):
                return
            server_id = None
            for o in pkt[DHCP].options:
                if isinstance(o, tuple) and len(o) >= 2 and o[0] == "server_id":
                    server_id = o[1]
                    break
            if server_id != self.server_ip:
                return
            client_mac = pkt[Ether].src
            ack = (Ether(src=self.server_mac, dst=client_mac) /
                   IP(src=self.server_ip, dst=self.offered_ip) /
                   UDP(sport=67, dport=68) /
                   BOOTP(op=2, chaddr=pkt[BOOTP].chaddr, yiaddr=self.offered_ip,
                         siaddr=self.server_ip, xid=pkt[BOOTP].xid, secs=pkt[BOOTP].secs) /
                   DHCP(options=[
                       ("message-type", "ack"),
                       ("server_id", self.server_ip),
                       ("lease_time", LEASE_TIME),
                       ("subnet_mask", "255.255.255.0"),
                       ("router", self.server_ip),
                       ("end")
                   ]))
            self._queue_packet(ack)
            self._log(f"Assigned: MAC={client_mac} -> IP={self.offered_ip}")
        except Exception:
            pass

    def handle_packet(self, pkt):
        if not self.running:
            return
        if DHCP not in pkt or not pkt[DHCP].options:
            return
        mtype = pkt[DHCP].options[0]
        if not isinstance(mtype, tuple):
            return
        t = mtype[1]
        if t == 1:
            self.respond_to_dhcp_discover(pkt)
        elif t == 3:
            self.respond_to_dhcp_request(pkt)

    def start_server(self):
        if self.running:
            return
        display = self.iface_combo.currentText()
        iface = self._iface_map.get(display)
        if not iface:
            self._log("Please select a network interface first.")
            return
        self._selected_iface = iface
        self.net_iface = iface
        self.server_ip = iface.ip
        self.server_mac = iface.mac or get_mac_from_ipconfig(iface.ip)
        if not self.server_mac:
            self._log(f"Cannot get the MAC address of interface [{iface.name}]")
            return
        self.offered_ip = self.ip_edit.text().strip() or DEFAULT_OFFERED_IP

        self.running = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.iface_combo.setEnabled(False)
        self.ip_edit.setEnabled(False)

        # Clear any leftover queue so old packets are not sent again
        with self._send_lock:
            self._send_queue.clear()
        self.e.clear()
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()
        self._sender_stop.clear()
        self._sender_thread = threading.Thread(target=self._sender_loop, daemon=True)
        self._sender_thread.start()
        self._log(f"Started on {iface.name} ({self.server_ip}), offering {self.offered_ip}")

    def _sniff_loop(self):
        """Background sniff loop: check the stop flag every 0.5 s so Stop
        takes effect promptly."""
        while not self.e.is_set():
            try:
                sniff(
                    iface=self.net_iface,
                    filter="udp and (port 67 or port 68)",
                    prn=self.handle_packet, store=False,
                    timeout=0.5,
                    stop_filter=lambda p: self.e.is_set()
                )
            except Exception:
                pass

    def stop_server(self):
        if not self.running:
            return
        self.running = False
        self.e.set()
        self._sender_stop.set()
        if self._sender_thread:
            self._sender_thread.join(timeout=2)
            self._sender_thread = None
        if self.sniff_thread:
            self.sniff_thread.join(timeout=3)
            self.sniff_thread = None
        # Clear the send queue to avoid re-sending stale packets
        with self._send_lock:
            self._send_queue.clear()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.iface_combo.setEnabled(True)
        self.ip_edit.setEnabled(True)
        self._log("Stopped.")

    def _sender_loop(self):
        while not self._sender_stop.is_set():
            pkt_to_send = None
            with self._send_lock:
                if self._send_queue:
                    pkt_to_send = self._send_queue.pop(0)
            if pkt_to_send is not None:
                try:
                    sendp(pkt_to_send, verbose=0, iface=self.net_iface)
                except Exception:
                    pass
            else:
                time.sleep(0.01)

    def _queue_packet(self, pkt):
        with self._send_lock:
            self._send_queue.append(pkt)

    def closeEvent(self, event):
        try:
            self.stop_server()
        except Exception:
            pass
        event.accept()


def main():
    app = QApplication(sys.argv)
    w = DHCPApp()
    w.show()
    app.exec_()


if __name__ == "__main__":
    main()
