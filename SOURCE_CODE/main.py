import sys
import winreg
import random
import subprocess
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                               QHBoxLayout, QLabel, QComboBox, QLineEdit,
                               QPushButton, QListWidget,
                               QMessageBox, QGroupBox)


class MacChanger(QMainWindow):
    def __init__(self):
        super().__init__()
        self.adapters = self.get_network_adapters()
        if not self.adapters:
            QMessageBox.critical(None, "Error", "No network adapters found!")
            sys.exit(1)
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("MacChanger - Administrator")
        self.setFixedSize(830, 500)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(10)
        layout.setContentsMargins(15, 15, 15, 15)

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
        self.mac_entry.setMinimumHeight(28)
        mac_layout.addWidget(self.mac_entry)

        btn_layout = QHBoxLayout()
        self.generate_btn = QPushButton("Generate MAC")
        self.generate_btn.setMinimumHeight(32)
        self.generate_btn.clicked.connect(self.generate_mac)
        btn_layout.addWidget(self.generate_btn)
        mac_layout.addLayout(btn_layout)

        action_layout = QHBoxLayout()
        self.apply_btn = QPushButton("APPLY MAC")
        self.apply_btn.setMinimumHeight(35)
        self.apply_btn.setStyleSheet(
            "QPushButton { background-color: #4CAF50; color: white; font-weight: bold; padding: 8px 16px; border: none; border-radius: 5px; min-height: 35px; } QPushButton:hover { background-color: #45a049; }")
        self.apply_btn.clicked.connect(self.apply_mac)
        action_layout.addWidget(self.apply_btn)

        self.reset_btn = QPushButton("RESET MAC")
        self.reset_btn.setMinimumHeight(35)
        self.reset_btn.setStyleSheet(
            "QPushButton { background-color: #f44336; color: white; font-weight: bold; padding: 8px 16px; border: none; border-radius: 5px; min-height: 35px; } QPushButton:hover { background-color: #da190b; }")
        self.reset_btn.clicked.connect(self.reset_mac)
        action_layout.addWidget(self.reset_btn)
        mac_layout.addLayout(action_layout)
        layout.addWidget(mac_group)

        pregen_group = QGroupBox("Pre-generated MAC Addresses")
        pregen_layout = QVBoxLayout(pregen_group)
        self.mac_listbox = QListWidget()
        self.mac_listbox.setMinimumHeight(100)
        pregenerated_macs = ["A2369F4C5D12", "B47E2A8C3F91", "C21C6E9A2B48", "E893F1A5C672"]
        self.mac_listbox.addItems(pregenerated_macs)
        self.mac_listbox.itemDoubleClicked.connect(self.on_mac_select)
        pregen_layout.addWidget(self.mac_listbox)
        layout.addWidget(pregen_group)

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
            print(f"Error reading adapters: {e}")
        return adapters

    def on_mac_select(self, item):
        self.mac_entry.setText(item.text())

    def generate_mac(self):
        first_char = random.choice("02468ACE")
        second_char = random.choice("26AE")
        remaining = "".join([random.choice("0123456789ABCDEF") for _ in range(10)])
        mac = first_char + second_char + remaining
        self.mac_entry.setText(mac)

    def validate_mac(self, mac):
        mac = mac.upper().replace(":", "").replace("-", "").replace(" ", "")
        if len(mac) != 12:
            return False
        try:
            int(mac, 16)
            first_octet = int(mac[:2], 16)
            if first_octet & 0x01:
                return False
            return True
        except ValueError:
            return False

    def show_reboot_dialog(self):
        reply = QMessageBox.question(self, "Reboot Required",
                                     "Computer needs to be rebooted for MAC address changes to take effect.\n\nDo you want to reboot now?",
                                     QMessageBox.Yes | QMessageBox.No)

        if reply == QMessageBox.Yes:
            try:
                subprocess.run(["shutdown", "/r", "/t", "0"], check=True)
            except subprocess.CalledProcessError as e:
                QMessageBox.critical(self, "Reboot Error", f"Failed to reboot system: {e}")

    def apply_mac(self):
        if self.adapter_combo.currentIndex() == -1:
            QMessageBox.critical(self, "Error", "Please select an adapter first")
            return

        mac = self.mac_entry.text().strip().upper().replace(":", "").replace("-", "").replace(" ", "")
        
        if not mac:
            QMessageBox.critical(self, "Error", "Please enter a MAC address")
            return

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
        if selected_index >= len(self.adapters):
            QMessageBox.critical(self, "Error", "Selected adapter is no longer available")
            return
        adapter = self.adapters[selected_index]

        try:
            key_path = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" + "\\" + \
                       adapter['path']
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "NetworkAddress", 0, winreg.REG_SZ, mac)

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
        if selected_index >= len(self.adapters):
            QMessageBox.critical(self, "Error", "Selected adapter is no longer available")
            return
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
                    self.show_reboot_dialog()
                except FileNotFoundError:
                    QMessageBox.information(self, "Info", "No custom MAC address found to reset")

        except PermissionError:
            QMessageBox.critical(self, "Permission Error", "Administrator privileges required")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to reset MAC address: {e}")


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