from pathlib import Path

TSHARK_PATH = Path(r"C:\Program Files\Wireshark\tshark.exe")
DUMPCAP_PATH = Path(r"C:\Program Files\Wireshark\dumpcap.exe")

print("TShark:", TSHARK_PATH.exists())
print("Dumpcap:", DUMPCAP_PATH.exists())