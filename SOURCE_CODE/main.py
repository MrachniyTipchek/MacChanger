import sys
import winreg
import random
import os
import subprocess
from datetime import datetime
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                               QHBoxLayout, QLabel, QComboBox, QLineEdit,
                               QPushButton, QListWidget, QTextEdit,
                               QMessageBox, QGroupBox)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont


class MacChanger(QMainWindow):
    def __init__(self):
        super().__init__()
        self.adapters = self.get_network_adapters()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("MacChanger - Administrator")
        self.setFixedSize(650, 650)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        title_label = QLabel("MacChanger")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        layout.addWidget(title_label)

        adapter_group = QGroupBox("Network Adapter Selection")
        adapter_layout = QVBoxLayout(adapter_group)
        adapter_layout.addWidget(QLabel("Select Network Adapter:"))
        self.adapter_combo = QComboBox()
        adapter_names = [f"{adapter['name']} ({adapter['guid']})" for adapter in self.adapters]
        self.adapter_combo.addItems(adapter_names)
        adapter_layout.addWidget(self.adapter_combo)
        layout.addWidget(adapter_group)

        mac_group = QGroupBox("MAC Address Operations")
        mac_layout = QVBoxLayout(mac_group)
        mac_layout.addWidget(QLabel("MAC Address:"))
        self.mac_entry = QLineEdit()
        mac_layout.addWidget(self.mac_entry)

        btn_layout = QHBoxLayout()
        self.generate_btn = QPushButton("Generate MAC")
        self.generate_btn.clicked.connect(self.generate_mac)
        btn_layout.addWidget(self.generate_btn)
        mac_layout.addLayout(btn_layout)

        action_layout = QHBoxLayout()
        self.apply_btn = QPushButton("APPLY MAC")
        self.apply_btn.setStyleSheet(
            "QPushButton { background-color: #4CAF50; color: white; font-weight: bold; padding: 10px; border: none; border-radius: 5px; } QPushButton:hover { background-color: #45a049; }")
        self.apply_btn.clicked.connect(self.apply_mac)
        action_layout.addWidget(self.apply_btn)

        self.reset_btn = QPushButton("RESET MAC")
        self.reset_btn.setStyleSheet(
            "QPushButton { background-color: #f44336; color: white; font-weight: bold; padding: 10px; border: none; border-radius: 5px; } QPushButton:hover { background-color: #da190b; }")
        self.reset_btn.clicked.connect(self.reset_mac)
        action_layout.addWidget(self.reset_btn)
        mac_layout.addLayout(action_layout)
        layout.addWidget(mac_group)

        pregen_group = QGroupBox("Pre-generated MAC Addresses")
        pregen_layout = QVBoxLayout(pregen_group)
        self.mac_listbox = QListWidget()
        pregenerated_macs = ["A2369F4C5D12", "B47E2A8C3F91", "D51C6E9A2B48", "E893F1A5C672"]
        self.mac_listbox.addItems(pregenerated_macs)
        self.mac_listbox.itemDoubleClicked.connect(self.on_mac_select)
        pregen_layout.addWidget(self.mac_listbox)
        layout.addWidget(pregen_group)

        log_group = QGroupBox("Operation Log")
        log_layout = QVBoxLayout(log_group)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        layout.addWidget(log_group)

        self.log("Application started with administrator privileges")

    def get_network_adapters(self):
        adapters = []
        try:
            key_path = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = f"{i:04d}"
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            try:
                                driver_desc = winreg.QueryValueEx(subkey, "DriverDesc")[0]
                                net_cfg_instance_id = winreg.QueryValueEx(subkey, "NetCfgInstanceId")[0]
                                if driver_desc and "WAN Miniport" not in driver_desc:
                                    adapters.append({
                                        'name': driver_desc,
                                        'path': subkey_name,
                                        'guid': net_cfg_instance_id
                                    })
                            except FileNotFoundError:
                                continue
                    except FileNotFoundError:
                        continue
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read adapters: {e}")
        return adapters

    def on_mac_select(self, item):
        self.mac_entry.setText(item.text())
        self.log(f"Selected MAC from list: {item.text()}")

    def generate_mac(self):
        mac = "".join([random.choice("0123456789ABCDEF") for _ in range(12)])
        self.mac_entry.setText(mac)
        self.log(f"Generated MAC: {mac}")

    def validate_mac(self, mac):
        mac = mac.upper().replace(":", "").replace("-", "")
        if len(mac) != 12:
            return False
        try:
            int(mac, 16)
            return True
        except ValueError:
            return False

    def show_reboot_dialog(self):
        reply = QMessageBox.question(self, "Reboot Required",
                                     "Computer needs to be rebooted for MAC address changes to take effect.\n\nDo you want to reboot now?",
                                     QMessageBox.Yes | QMessageBox.No)

        if reply == QMessageBox.Yes:
            self.log("Initiating system reboot...")
            try:
                subprocess.run(["shutdown", "/r", "/t", "0"], check=True, shell=True)
            except subprocess.CalledProcessError as e:
                QMessageBox.critical(self, "Reboot Error", f"Failed to reboot system: {e}")

    def apply_mac(self):
        if self.adapter_combo.currentIndex() == -1:
            QMessageBox.critical(self, "Error", "Please select an adapter first")
            return

        mac = self.mac_entry.text().upper().replace(":", "").replace("-", "")

        if not self.validate_mac(mac):
            QMessageBox.critical(self, "Error", "Invalid MAC address format. Must be 12 hex characters (0-9, A-F)")
            return

        reply = QMessageBox.question(self, "Confirm MAC Change",
                                     f"Are you sure you want to change MAC address to:\n{mac}?\n\n"
                                     f"Adapter: {self.adapter_combo.currentText().split(' (')[0]}",
                                     QMessageBox.Yes | QMessageBox.No)

        if reply != QMessageBox.Yes:
            return

        selected_index = self.adapter_combo.currentIndex()
        adapter = self.adapters[selected_index]

        try:
            key_path = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" + "\\" + \
                       adapter['path']
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "NetworkAddress", 0, winreg.REG_SZ, mac)

            self.log(f"MAC address {mac} applied to {adapter['name']}")
            self.show_reboot_dialog()

        except PermissionError:
            QMessageBox.critical(self, "Permission Error", "Administrator privileges required")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to apply MAC address: {e}")

    def reset_mac(self):
        if self.adapter_combo.currentIndex() == -1:
            QMessageBox.critical(self, "Error", "Please select an adapter first")
            return

        selected_index = self.adapter_combo.currentIndex()
        adapter = self.adapters[selected_index]

        reply = QMessageBox.question(self, "Confirm MAC Reset",
                                     f"Are you sure you want to reset MAC address to default?\n\n"
                                     f"Adapter: {self.adapter_combo.currentText().split(' (')[0]}",
                                     QMessageBox.Yes | QMessageBox.No)

        if reply != QMessageBox.Yes:
            return

        try:
            key_path = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" + "\\" + \
                       adapter['path']
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as key:
                try:
                    winreg.DeleteValue(key, "NetworkAddress")
                    self.log(f"MAC address reset for {adapter['name']}")
                    self.show_reboot_dialog()
                except FileNotFoundError:
                    QMessageBox.information(self, "Info", "No custom MAC address found to reset")

        except PermissionError:
            QMessageBox.critical(self, "Permission Error", "Administrator privileges required")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to reset MAC address: {e}")

    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")


def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if __name__ == "__main__":
    if not is_admin():
        QMessageBox.critical(None, "Admin Rights Required", "This application must be run as Administrator")
        sys.exit(1)

    app = QApplication(sys.argv)
    window = MacChanger()
    window.show()
    sys.exit(app.exec())