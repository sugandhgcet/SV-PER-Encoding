#!/usr/bin/env python3
#
# IEC 61850-9-2 SV Simulator
#
# This application simulates the publishing of IEC 61850-9-2 Sampled Values (SV)
# streams using both BER (Basic Encoding Rules) and a manual, hard-coded
# PER (Packed Encoding Rules) encoder.
# It also includes a BER decoder tab to sniff and parse SV streams from the network.
#
# Requires:
# - PyQt6: pip install PyQt6
# - pyqtgraph: pip install pyqtgraph
# - scapy: pip install scapy
# - numpy: pip install numpy
#
# NOTE: This version abandons 'asn1tools' and 'pyasn1' for PER encoding
# and uses a manual, hard-coded PER builder to resolve persistent
# ASN.1 syntax/compiler errors.
#

import sys
import time
import struct
import numpy as np
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QComboBox, QDoubleSpinBox, QSpinBox,
    QFormLayout, QTabWidget, QTextEdit, QGroupBox
)
from PyQt6.QtCore import QObject, QThread, pyqtSignal, pyqtSlot, Qt
import pyqtgraph as pg
from scapy.all import Ether, Dot1Q, Raw, sendp, sniff, get_if_list, get_if_hwaddr

# ==============================================================================
#  1. SV PUBLISHER LOGIC (Manual ASN.1 BER Encoding)
# ==============================================================================

class SVWorker(QObject):
    """
    Worker thread for generating and transmitting SV packets (BER Encoded).
    """
    new_data_signal = pyqtSignal(np.ndarray)
    packets_sent_signal = pyqtSignal(int)

    def __init__(self, config):
        super().__init__()
        self.config = config
        self._is_running = True
        self.packet_count = 0

    def _create_tlv(self, tag, value_bytes):
        """Creates a simple ASN.1 Type-Length-Value structure."""
        tag_byte = bytes([tag])
        # This assumes length is less than 128
        len_byte = bytes([len(value_bytes)])
        return tag_byte + len_byte + value_bytes

    def _encode_apdu_ber(self, svID, smpCnt, confRev, smpSynch, data_set):
        """
        Encodes the APDU payload using manual ASN.1 BER construction.
        """
        # 1. Create TLVs for each field inside the ASDU
        # [APPLICATION 0] VisibleString
        svid_tlv = self._create_tlv(0x80, svID.encode('ascii'))
        # [APPLICATION 2] INTEGER
        smpcnt_tlv = self._create_tlv(0x82, smpCnt.to_bytes(2, 'big'))
        # [APPLICATION 3] INTEGER
        confrev_tlv = self._create_tlv(0x83, confRev.to_bytes(4, 'big'))
        # [APPLICATION 5] INTEGER
        smpSynch_val = 2 # 0=local, 1=ptp, 2=globalGps
        smpsynch_tlv = self._create_tlv(0x85, smpSynch_val.to_bytes(1, 'big'))
        # [APPLICATION 7] OCTET STRING
        dataset_tlv = self._create_tlv(0x87, data_set)

        # 2. Concatenate the field TLVs to form the content of the ASDU
        asdu_content = svid_tlv + smpcnt_tlv + confrev_tlv + smpsynch_tlv + dataset_tlv
        
        # 3. Wrap the content in an ASDU SEQUENCE tag (0x30)
        asdu_tlv = self._create_tlv(0x30, asdu_content)

        # 4. Create the 'seqASDU' (a constructed type with tag [APPLICATION 2] = 0xA2)
        seq_asdu_tlv = self._create_tlv(0xA2, asdu_tlv)

        # 5. Create the 'noASDU' TLV ([APPLICATION 0] = 0x80)
        no_asdu_tlv = self._create_tlv(0x80, (1).to_bytes(1, 'big'))

        # 6. Concatenate to form the content of the savPDU
        sav_pdu_content = no_asdu_tlv + seq_asdu_tlv
        
        # 7. Wrap in the final savPDU application tag ([APPLICATION 0] = 0x60)
        sav_pdu_tlv = self._create_tlv(0x60, sav_pdu_content)
        
        return sav_pdu_tlv

    @pyqtSlot()
    def run(self):
        freq = self.config['freq']
        sps = self.config['sps']
        sampling_rate = freq * sps
        time_step = 1.0 / sampling_rate

        smpCnt = 0
        confRev = 1
        smpSynch = 2  # 0=local, 1=ptp, 2=globalGps

        vlan_layer = Dot1Q(vlan=self.config['vlan_id'], prio=4) if self.config['vlan_id'] > 0 else None

        # Pre-generate one full cycle of waveform data for efficiency
        t = np.arange(0, sps) * time_step
        va = self.config['v_amp'] * np.sin(2 * np.pi * freq * t)
        vb = self.config['v_amp'] * np.sin(2 * np.pi * freq * t - 2 * np.pi / 3)
        vc = self.config['v_amp'] * np.sin(2 * np.pi * freq * t + 2 * np.pi / 3)
        ia = self.config['i_amp'] * np.sin(2 * np.pi * freq * t)
        ib = self.config['i_amp'] * np.sin(2 * np.pi * freq * t - 2 * np.pi / 3)
        ic = self.config['i_amp'] * np.sin(2 * np.pi * freq * t + 2 * np.pi / 3)

        gui_buffer = []
        
        while self._is_running:
            start_time = time.perf_counter()
            idx = smpCnt % sps

            # According to 9-2LE: Currents in mA, Voltages in 10mV
            data_values = [
                int(ia[idx] * 1000), 0, int(ib[idx] * 1000), 0,
                int(ic[idx] * 1000), 0, 0, 0,  # IN, INq
                int(va[idx] * 100), 0, int(vb[idx] * 100), 0,
                int(vc[idx] * 100), 0, 0, 0,  # VN, VNq
            ]
            # 8x 4-byte int (val) + 8x 4-byte int (quality) = 64 bytes
            data_set_bytes = struct.pack('!16i', *data_values)

            apdu_payload = self._encode_apdu_ber(
                self.config['sv_id'], smpCnt, confRev, smpSynch, data_set_bytes
            )

            # SV Header: APPID, Length, Reserved1 (Simulate bit set), Reserved2
            sv_header = struct.pack('>HHHH', int(self.config['appid'], 16), len(apdu_payload) + 8, 0x8000, 0)
            
            ether_layer = Ether(src=self.config['src_mac'], dst=self.config['dst_mac'], type=0x88BA)
            
            if vlan_layer:
                packet = ether_layer / vlan_layer / Raw(load=sv_header + apdu_payload)
            else:
                packet = ether_layer / Raw(load=sv_header + apdu_payload)

            sendp(packet, iface=self.config['iface'], verbose=0)

            self.packet_count += 1
            smpCnt = (smpCnt + 1) % sampling_rate # smpCnt loops 0..[sps*freq-1]

            # Update GUI
            gui_buffer.append(data_values)
            if len(gui_buffer) >= 100: # Update GUI every 100 samples
                self.new_data_signal.emit(np.array(gui_buffer))
                self.packets_sent_signal.emit(self.packet_count)
                gui_buffer = []

            # Precise sleep to maintain sampling rate
            elapsed = time.perf_counter() - start_time
            sleep_time = time_step - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)
            else:
                # Yield control to OS to prevent GUI freeze
                time.sleep(0)

    def stop(self):
        self._is_running = False

# ==============================================================================
#  2. SV PUBLISHER LOGIC (Manual ASN.1 PER Encoding)
# ==============================================================================

class SVWorkerPER(QObject):
    """
    Worker thread for generating and transmitting SV packets (MANUAL PER Encoded).
    This worker manually constructs the PER byte string, bypassing
    asn1tools/pyasn1 entirely to avoid compiler errors.
    """
    log_signal = pyqtSignal(str)

    def __init__(self, config):
        super().__init__()
        self.config = config
        self._is_running = True
        self.packet_count = 0
        
        # --- Pre-calculate static parts of the PER payload ---
        # Based on the (tag-less) schema:
        # SavPDU ::= SEQUENCE {
        #    noASDU      INTEGER (0..255),           -- 1 byte
        #    seqASDU     SEQUENCE (SIZE(1..1)) OF ASDU -- 0 bytes (implicit length 1)
        # }
        # ASDU ::= SEQUENCE {
        #    svID        VisibleString,              -- 1 byte len + N bytes data
        #    smpCnt      INTEGER (0..65535),         -- 2 bytes
        #    confRev     INTEGER (0..4294967295),    -- 4 bytes
        #    smpSynch    ENUMERATED { local(0), ptp(1), globalGps(2) }, -- 1 byte
        #    DataSet     OCTET STRING                -- 1 byte len + N bytes data
        # }
        
        # 1. SavPDU.noASDU (Value: 1)
        self.per_noASDU = (1).to_bytes(1, 'big')
        
        # 2. SavPDU.seqASDU (Implicit length 1, 0 bytes)
        
        # 3. ASDU.svID (e.g., "SimulatedSVStream")
        svid_str = self.config['sv_id'].encode('ascii')
        # PER length prefix (short form, < 128)
        self.per_svID_len = len(svid_str).to_bytes(1, 'big')
        self.per_svID_data = svid_str
        
        # 4. ASDU.smpCnt (Dynamic, 2 bytes)
        
        # 5. ASDU.confRev (Dynamic, 4 bytes)
        
        # 6. ASDU.smpSynch (Value: 2 for 'globalGps')
        # Encodes as an integer index (0, 1, or 2). Fits in 1 byte.
        self.per_smpSynch = (2).to_bytes(1, 'big')
        
        # 7. ASDU.DataSet (Length: 64 bytes)
        # 16 ints * 4 bytes/int = 64
        self.per_DataSet_len = (64).to_bytes(1, 'big')

    def _encode_apdu_per(self, smpCnt, confRev, data_set_bytes):
        """
        Manually constructs the APDU payload using Aligned PER rules.
        """
        # Pack the dynamic fields
        smpCnt_bytes = smpCnt.to_bytes(2, 'big')
        confRev_bytes = confRev.to_bytes(4, 'big')

        # Concatenate all parts in the exact schema order
        apdu_payload = (
            self.per_noASDU +
            self.per_svID_len + self.per_svID_data +
            smpCnt_bytes +
            confRev_bytes +
            self.per_smpSynch +
            self.per_DataSet_len + data_set_bytes
        )
        return apdu_payload

    @pyqtSlot()
    def run(self):
        freq = self.config['freq']
        sps = self.config['sps']
        sampling_rate = freq * sps
        time_step = 1.0 / sampling_rate

        smpCnt = 0
        confRev = 1
        # smpSynch is hard-coded to 2 ('globalGps') in __init__

        vlan_layer = Dot1Q(vlan=self.config['vlan_id'], prio=4) if self.config['vlan_id'] > 0 else None

        # Pre-generate waveforms
        t = np.arange(0, sps) * time_step
        va = self.config['v_amp'] * np.sin(2 * np.pi * freq * t)
        vb = self.config['v_amp'] * np.sin(2 * np.pi * freq * t - 2 * np.pi / 3)
        vc = self.config['v_amp'] * np.sin(2 * np.pi * freq * t + 2 * np.pi / 3)
        ia = self.config['i_amp'] * np.sin(2 * np.pi * freq * t)
        ib = self.config['i_amp'] * np.sin(2 * np.pi * freq * t - 2 * np.pi / 3)
        ic = self.config['i_amp'] * np.sin(2 * np.pi * freq * t + 2 * np.pi / 3)
        
        while self._is_running:
            start_time = time.perf_counter()
            idx = smpCnt % sps

            data_values = [
                int(ia[idx] * 1000), 0, int(ib[idx] * 1000), 0,
                int(ic[idx] * 1000), 0, 0, 0,
                int(va[idx] * 100), 0, int(vb[idx] * 100), 0,
                int(vc[idx] * 100), 0, 0, 0,
            ]
            # 16 * 4-byte integers = 64 bytes
            data_set_bytes = struct.pack('!16i', *data_values)
            
            # --- Use the new manual PER encoder ---
            apdu_payload = self._encode_apdu_per(
                smpCnt, confRev, data_set_bytes
            )
            # ---
            
            # SV Header: APPID, Length, Reserved1 (Simulate bit set), Reserved2
            # Length = APDU + 8-byte SV header
            sv_header = struct.pack('>HHHH', int(self.config['appid'], 16), len(apdu_payload) + 8, 0x8000, 0)
            
            ether_layer = Ether(src=self.config['src_mac'], dst=self.config['dst_mac'], type=0x88BA)
            
            if vlan_layer:
                packet = ether_layer / vlan_layer / Raw(load=sv_header + apdu_payload)
            else:
                packet = ether_layer / Raw(load=sv_header + apdu_payload)

            sendp(packet, iface=self.config['iface'], verbose=0)

            self.packet_count += 1
            smpCnt = (smpCnt + 1) % sampling_rate

            if self.packet_count % 100 == 0: # Log every 100 packets
                frame_len = len(packet)
                self.log_signal.emit(f"Sent Pkt: {self.packet_count} | smpCnt: {smpCnt} | Frame Length: {frame_len} bytes")

            # Precise sleep
            elapsed = time.perf_counter() - start_time
            sleep_time = time_step - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)
            else:
                time.sleep(0)

    def stop(self):
        self._is_running = False

# ==============================================================================
#  3. SV DECODER LOGIC (Manual ASN.1 BER Parsing)
# ==============================================================================

class DecoderWorker(QObject):
    """
    Decodes SV packets (BER encoded) from the network.
    NOTE: This will *NOT* decode the PER packets from the other tab.
    """
    packet_decoded = pyqtSignal(str)

    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.running = False

    def _parse_tlv(self, data):
        """Parses a stream of BER TLVs and returns a dictionary."""
        decoded = {}
        i = 0
        try:
            while i < len(data):
                tag = data[i]
                length = data[i+1]
                value_bytes = data[i+2 : i+2+length]
                
                if tag == 0x80 and len(decoded) == 0: # noASDU
                     decoded['noASDU'] = int.from_bytes(value_bytes, 'big')
                elif tag == 0xA2: # seqASDU
                    decoded['seqASDU'] = self._parse_asdu_sequence(value_bytes)
                
                # --- This part is for parsing *inside* the ASDU ---
                elif tag == 0x80: decoded['svID'] = value_bytes.decode('ascii')
                elif tag == 0x82: decoded['smpCnt'] = int.from_bytes(value_bytes, 'big')
                elif tag == 0x83: decoded['confRev'] = int.from_bytes(value_bytes, 'big')
                elif tag == 0x85: decoded['smpSynch'] = int.from_bytes(value_bytes, 'big')
                elif tag == 0x87:
                    d = struct.unpack('!16i', value_bytes)
                    decoded['DataSet'] = {
                        'Ia': d[0]/1000.0, 'Iaq': hex(d[1]), 'Ib': d[2]/1000.0, 'Ibq': hex(d[3]),
                        'Ic': d[4]/1000.0, 'Icq': hex(d[5]), 'In': d[6]/1000.0, 'Inq': hex(d[7]),
                        'Va': d[8]/100.0, 'Vaq': hex(d[9]), 'Vb': d[10]/100.0, 'Vbq': hex(d[11]),
                        'Vc': d[12]/100.0, 'Vcq': hex(d[13]), 'Vn': d[14]/100.0, 'Vnq': hex(d[15]),
                    }
                i += 2 + length
        except Exception as e:
            return {'Error': f"TLV Parse Error: {e}", 'Data': data.hex()}
        return decoded

    def _parse_asdu_sequence(self, data):
        """Parses the content of the seqASDU TLV."""
        if data[0] != 0x30: # Check for SEQUENCE tag
            return {"Error": "ASDU SEQUENCE (0x30) tag not found"}
        asdu_len = data[1]
        asdu_content = data[2 : 2+asdu_len]
        return self._parse_tlv(asdu_content) # Recursively parse inner TLVs


    def _decode_sv_packet(self, packet):
        if Raw not in packet: return None
        payload = packet.load
        
        try:
            appid, length, res1, res2 = struct.unpack('>HHHH', payload[:8])
            is_simulated = (res1 & 0x8000) != 0
            
            apdu_data = payload[8:]
            
            # Manually parse the APDU (BER)
            sav_pdu_tag = apdu_data[0]
            if sav_pdu_tag != 0x60: return "Not a savPDU (0x60)"
            
            sav_pdu_len = apdu_data[1]
            sav_pdu_content = apdu_data[2 : 2+sav_pdu_len]
            
            decoded = {'APPID': hex(appid), 'Simulated': is_simulated}
            
            # Parse the fields inside the savPDU
            sav_pdu_fields = self._parse_tlv(sav_pdu_content)
            decoded.update(sav_pdu_fields)
            
            return decoded
        except Exception as e:
            return f"Packet Decode Error: {e}"

    def _process_packet(self, packet):
        decoded_data = self._decode_sv_packet(packet)
        if isinstance(decoded_data, dict):
            output = f"--- SV Packet (BER Decoded) ---\n"
            output += f"  Source MAC: {packet[Ether].src}\n"
            
            def format_dict(d, indent=1):
                s = ""
                idt_str = "  " * indent
                for k, v in d.items():
                    if isinstance(v, dict):
                        s += f"{idt_str}{k}:\n"
                        s += format_dict(v, indent + 1)
                    else:
                        val_str = f"{v:.4f}" if isinstance(v, float) else f"{v}"
                        s += f"{idt_str}{k:<10}: {val_str}\n"
                return s
            
            output += format_dict(decoded_data)
            self.packet_decoded.emit(output)
        elif decoded_data:
            # Log simple error strings
            self.packet_decoded.emit(f"Skipped Packet: {decoded_data}")


    @pyqtSlot()
    def run(self):
        self.running = True
        # Loop with a timeout to prevent sniff from blocking indefinitely
        while self.running:
            try:
                sniff(iface=self.iface, filter="ether proto 0x88ba", prn=self._process_packet, stop_filter=lambda p: not self.running, timeout=1)
            except Exception as e:
                self.packet_decoded.emit(f"\n--- SNIFFER ERROR ---\n{e}\nCheck interface and permissions.\n")
                time.sleep(1) # Avoid spamming errors

    def stop(self):
        self.running = False

# ==============================================================================
#  4. MAIN GUI APPLICATION
# ==============================================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IEC 61850-9-2 SV Simulator (BER/PER)")
        self.setGeometry(100, 100, 1200, 800)

        # --- THEME AND STYLING ---
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #f0f0f0;
                color: #000000; /* Default font color to black */
            }
            QGroupBox {
                background-color: #e0e8f0;
                border: 1px solid #c0c0c0;
                border-radius: 5px;
                margin-top: 1ex; 
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 3px;
                color: #000000;
            }
            QLabel {
                color: #000000;
                font-weight: bold;
            }
            QLineEdit, QTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {
                background-color: #ffffff;
                border: 1px solid #c0c0c0;
                border-radius: 4px;
                padding: 4px;
                color: #000000;
            }
            QPushButton {
                background-color: #0078d7;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
            QPushButton:disabled {
                background-color: #a0a0a0;
            }
            QTabWidget::pane {
                border-top: 1px solid #c0c0c0;
            }
            QTabBar::tab {
                background: #d0d0d0;
                border: 1px solid #c0c0c0;
                padding: 6px;
                border-bottom-left-radius: 4px;
                border-bottom-right-radius: 4px;
                color: #000000;
            }
            QTabBar::tab:selected {
                background: #e0e8f0;
                margin-bottom: -1px; 
            }
        """)

        # --- Worker Threads ---
        self.ber_worker = None
        self.ber_thread = None
        self.per_worker = None
        self.per_thread = None
        self.decoder_worker = None
        self.decoder_thread = None

        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(10, 10, 10, 5)
        main_layout.setSpacing(10)

        self.tabs = QTabWidget()
        
        # --- Create Config Widgets (SHARED) ---
        self._create_shared_config_widgets()
        
        # --- Create Tabs ---
        self._create_publisher_ber_tab()
        self._create_publisher_per_tab()
        self._create_decoder_tab()
        
        main_layout.addWidget(self.tabs)

        credit_label = QLabel("<b>Developed by Sugandh Pratap</b>")
        credit_label.setStyleSheet("font-size: 12pt; color: #333333;")
        credit_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(credit_label)

        self.setCentralWidget(main_widget)
        
        # Set default interface
        if self.iface_in.count() > 0:
            default_iface = self.iface_in.itemText(0)
            self.iface_in.setCurrentText(default_iface)
            self.decoder_iface_edit.setCurrentText(default_iface)
            try:
                self.src_mac_in.setText(get_if_hwaddr(default_iface))
            except Exception:
                self.src_mac_in.setText("00:00:00:00:00:00")

    def _create_shared_config_widgets(self):
        """Creates the config widgets that will be used by both publisher tabs."""
        
        # --- Network Config ---
        self.net_config_group = QGroupBox("Network Configuration")
        net_form = QFormLayout()
        available_ifaces = get_if_list()
        self.iface_in = QComboBox()
        self.iface_in.addItems(available_ifaces)
        
        self.dst_mac_in = QLineEdit("01:0C:CD:04:00:01")
        self.src_mac_in = QLineEdit() # Will be set by handler
        self.iface_in.currentTextChanged.connect(
            lambda iface: self.src_mac_in.setText(get_if_hwaddr(iface) if iface else "00:00:00:00:00:00")
        )

        self.vlan_id_in = QSpinBox(minimum=0, maximum=4095, value=0)
        self.appid_in = QLineEdit("4000")
        self.svid_in = QLineEdit("SimulatedSVStream")
        
        net_form.addRow("Network Interface:", self.iface_in)
        net_form.addRow("Destination MAC:", self.dst_mac_in)
        net_form.addRow("Source MAC:", self.src_mac_in)
        net_form.addRow("VLAN ID (0=off):", self.vlan_id_in)
        net_form.addRow("APPID (hex):", self.appid_in)
        net_form.addRow("svID:", self.svid_in)
        self.net_config_group.setLayout(net_form)
        
        # --- Signal Config ---
        self.signal_config_group = QGroupBox("Signal Configuration")
        signal_form = QFormLayout()
        self.freq_in = QComboBox()
        self.freq_in.addItems(["50", "60"])
        self.sps_in = QComboBox()
        self.sps_in.addItems(["80", "256"]) # 9-2LE standards
        self.v_amp_in = QDoubleSpinBox(minimum=0, maximum=100000.0, value=100.0, singleStep=10.0)
        self.i_amp_in = QDoubleSpinBox(minimum=0, maximum=10000.0, value=5.0, singleStep=0.5)

        signal_form.addRow("Frequency (Hz):", self.freq_in)
        signal_form.addRow("Samples/Cycle:", self.sps_in)
        signal_form.addRow("Voltage Amplitude (V):", self.v_amp_in)
        signal_form.addRow("Current Amplitude (A):", self.i_amp_in)
        self.signal_config_group.setLayout(signal_form)
        
    def _create_publisher_ber_tab(self):
        tab = QWidget()
        main_layout = QHBoxLayout(tab)
        
        # --- Left Controls Column ---
        controls_col = QVBoxLayout()
        controls_col.addWidget(self.net_config_group)
        controls_col.addWidget(self.signal_config_group)
        
        # --- Control Box ---
        control_group = QGroupBox("Publisher Controls (BER)")
        control_layout = QVBoxLayout()
        self.ber_start_button = QPushButton("Start Simulation (BER)")
        self.ber_start_button.clicked.connect(self.start_simulation_ber)
        self.ber_stop_button = QPushButton("Stop Simulation (BER)", enabled=False)
        self.ber_stop_button.clicked.connect(self.stop_simulation_ber)
        
        self.ber_status_label = QLabel("Status: Stopped")
        self.ber_packets_label = QLabel("Packets Sent: 0")
        
        control_layout.addWidget(self.ber_start_button)
        control_layout.addWidget(self.ber_stop_button)
        control_layout.addWidget(self.ber_status_label)
        control_layout.addWidget(self.ber_packets_label)
        control_group.setLayout(control_layout)
        
        controls_col.addWidget(control_group)
        controls_col.addStretch()
        
        main_layout.addLayout(controls_col, 1)

        # --- Right Plotting Column ---
        plot_widget = QWidget()
        plot_layout = QVBoxLayout(plot_widget)
        pg.setConfigOption('background', 'w'); pg.setConfigOption('foreground', 'k')
        self.plot_v = pg.PlotWidget(title="Voltages")
        self.plot_i = pg.PlotWidget(title="Currents")
        plot_layout.addWidget(self.plot_v); plot_layout.addWidget(self.plot_i)
        self.plot_v.addLegend(); self.plot_i.addLegend()
        self.v_curves = {
            'Va': self.plot_v.plot(pen='r', name='Va'),
            'Vb': self.plot_v.plot(pen='g', name='Vb'),
            'Vc': self.plot_v.plot(pen='b', name='Vc')
        }
        self.i_curves = {
            'Ia': self.plot_i.plot(pen='r', name='Ia'),
            'Ib': self.plot_i.plot(pen='g', name='Ib'),
            'Ic': self.plot_i.plot(pen='b', name='Ic')
        }
        self.plot_data_v = np.zeros((500, 3)); self.plot_data_i = np.zeros((500, 3))
        main_layout.addWidget(plot_widget, 3)
        self.tabs.addTab(tab, "SV Publisher (BER)")

    def _create_publisher_per_tab(self):
        tab = QWidget()
        main_layout = QVBoxLayout(tab)
        
        # --- Control Box ---
        control_group = QGroupBox("Publisher Controls (PER)")
        control_layout = QVBoxLayout()
        self.per_start_button = QPushButton("Start Simulation (PER)")
        self.per_start_button.clicked.connect(self.start_simulation_per)
        self.per_stop_button = QPushButton("Stop Simulation (PER)", enabled=False)
        self.per_stop_button.clicked.connect(self.stop_simulation_per)
        
        self.per_status_label = QLabel("Status: Stopped")
        
        control_layout.addWidget(self.per_start_button)
        control_layout.addWidget(self.per_stop_button)
        control_layout.addWidget(self.per_status_label)
        
        control_group.setLayout(control_layout) # <-- ADD THIS MISSING LINE
        
        main_layout.addWidget(control_group)

        # --- Log Output ---
        log_group = QGroupBox("PER Publisher Log")
        log_layout = QVBoxLayout()
        self.per_log_output = QTextEdit(readOnly=True)
        self.per_log_output.setStyleSheet("font-family: 'Courier New', monospace; color: #000000;")
        log_layout.addWidget(self.per_log_output)
        log_group.setLayout(log_layout)
        
        main_layout.addWidget(log_group)
        self.tabs.addTab(tab, "SV Publisher (PER)")

    def _create_decoder_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        decoder_group = QGroupBox("Decoder Controls (BER only)")
        decoder_layout = QVBoxLayout()
        
        iface_layout = QHBoxLayout()
        iface_layout.addWidget(QLabel("Interface:"))
        self.decoder_iface_edit = QComboBox()
        self.decoder_iface_edit.addItems(get_if_list())
        iface_layout.addWidget(self.decoder_iface_edit)
        decoder_layout.addLayout(iface_layout)
        
        button_layout = QHBoxLayout()
        self.start_decode_button = QPushButton("Start Sniffing")
        self.stop_decode_button = QPushButton("Stop Sniffing", enabled=False)
        button_layout.addWidget(self.start_decode_button)
        button_layout.addWidget(self.stop_decode_button)
        decoder_layout.addLayout(button_layout)
        decoder_group.setLayout(decoder_layout)
        
        self.decoder_output = QTextEdit(readOnly=True)
        self.decoder_output.setStyleSheet("font-family: 'Courier New', monospace; color: #000000;")
        
        layout.addWidget(decoder_group)
        layout.addWidget(self.decoder_output)
        
        self.start_decode_button.clicked.connect(self.start_decoding)
        self.stop_decode_button.clicked.connect(self.stop_decoding)
        self.tabs.addTab(tab, "SV Decoder (BER)")

    def _get_shared_config(self):
        """Gathers all config values from the shared widgets."""
        return {
            "iface": self.iface_in.currentText(),
            "dst_mac": self.dst_mac_in.text(),
            "src_mac": self.src_mac_in.text(),
            "vlan_id": self.vlan_id_in.value(),
            "appid": self.appid_in.text(),
            "sv_id": self.svid_in.text(),
            "freq": int(self.freq_in.currentText()),
            "sps": int(self.sps_in.currentText()),
            "v_amp": self.v_amp_in.value(),
            "i_amp": self.i_amp_in.value(),
        }

    def _set_config_widgets_enabled(self, enabled):
        """Enables or disables all config widgets."""
        self.net_config_group.setEnabled(enabled)
        self.signal_config_group.setEnabled(enabled)

    def start_simulation_ber(self):
        config = self._get_shared_config()
        self.ber_thread = QThread()
        self.ber_worker = SVWorker(config)
        self.ber_worker.moveToThread(self.ber_thread)
        self.ber_worker.new_data_signal.connect(self.update_plots)
        self.ber_worker.packets_sent_signal.connect(self.update_ber_packet_count)
        self.ber_thread.started.connect(self.ber_worker.run)
        self.ber_thread.start()
        
        self.ber_start_button.setEnabled(False)
        self.ber_stop_button.setEnabled(True)
        self.per_start_button.setEnabled(False) # Disable other start button
        self._set_config_widgets_enabled(False)
        self.ber_status_label.setText("Status: Running")

    def stop_simulation_ber(self):
        if self.ber_worker: self.ber_worker.stop()
        if self.ber_thread: self.ber_thread.quit(); self.ber_thread.wait()
        
        self.ber_start_button.setEnabled(True)
        self.ber_stop_button.setEnabled(False)
        self.per_start_button.setEnabled(True) # Re-enable other start
        self._set_config_widgets_enabled(True)
        self.ber_status_label.setText("Status: Stopped")

    def start_simulation_per(self):
        config = self._get_shared_config()
        
        self.per_log_output.clear()
        self.per_log_output.append(f"Starting PER simulation on '{config['iface']}'...")
        
        self.per_thread = QThread()
        self.per_worker = SVWorkerPER(config)
        self.per_worker.moveToThread(self.per_thread)
        self.per_worker.log_signal.connect(self.per_log_output.append)
        self.per_thread.started.connect(self.per_worker.run)
        self.per_thread.start()
        
        self.per_start_button.setEnabled(False)
        self.per_stop_button.setEnabled(True)
        self.ber_start_button.setEnabled(False) # Disable other start button
        self._set_config_widgets_enabled(False)
        self.per_status_label.setText("Status: Running")

    def stop_simulation_per(self):
        if self.per_worker: self.per_worker.stop()
        if self.per_thread: self.per_thread.quit(); self.per_thread.wait()
        
        self.per_start_button.setEnabled(True)
        self.per_stop_button.setEnabled(False)
        self.ber_start_button.setEnabled(True) # Re-enable other start
        self._set_config_widgets_enabled(True)
        self.per_status_label.setText("Status: Stopped")
        self.per_log_output.append("Simulation stopped.")

    def start_decoding(self):
        iface = self.decoder_iface_edit.currentText()
        if not iface:
            self.decoder_output.append("Error: No interface selected.")
            return
            
        self.decoder_output.clear()
        self.decoder_output.append(f"Starting BER sniffer on interface '{iface}'...")
        self.decoder_thread = QThread()
        self.decoder_worker = DecoderWorker(iface)
        self.decoder_worker.moveToThread(self.decoder_thread)
        self.decoder_worker.packet_decoded.connect(self.decoder_output.append)
        self.decoder_thread.started.connect(self.decoder_worker.run)
        self.decoder_thread.start()
        
        self.start_decode_button.setEnabled(False)
        self.stop_decode_button.setEnabled(True)
        self.decoder_iface_edit.setEnabled(False)

    def stop_decoding(self):
        if self.decoder_worker: self.decoder_worker.stop()
        if self.decoder_thread: self.decoder_thread.quit(); self.decoder_thread.wait()
        
        self.decoder_output.append("\nSniffer stopped.")
        self.start_decode_button.setEnabled(True)
        self.stop_decode_button.setEnabled(False)
        self.decoder_iface_edit.setEnabled(True)

    @pyqtSlot(np.ndarray)
    def update_plots(self, data_batch):
        # Correctly slice the data for plotting
        currents = data_batch[:, [0, 2, 4]] / 1000.0
        voltages = data_batch[:, [8, 10, 12]] / 100.0
        n = len(data_batch)
        
        self.plot_data_i = np.roll(self.plot_data_i, -n, axis=0)
        self.plot_data_i[-n:] = currents
        self.plot_data_v = np.roll(self.plot_data_v, -n, axis=0)
        self.plot_data_v[-n:] = voltages
        
        self.i_curves['Ia'].setData(self.plot_data_i[:, 0])
        self.i_curves['Ib'].setData(self.plot_data_i[:, 1])
        self.i_curves['Ic'].setData(self.plot_data_i[:, 2])
        self.v_curves['Va'].setData(self.plot_data_v[:, 0])
        self.v_curves['Vb'].setData(self.plot_data_v[:, 1])
        self.v_curves['Vc'].setData(self.plot_data_v[:, 2])

    @pyqtSlot(int)
    def update_ber_packet_count(self, count):
        self.ber_packets_label.setText(f"Packets Sent: {count}")

    def closeEvent(self, event):
        self.stop_simulation_ber()
        self.stop_simulation_per()
        self.stop_decoding()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


