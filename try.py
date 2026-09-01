from scapy.all import rdpcap

packets = rdpcap("deneme.pcapng")

print("Packet Count:", len(packets))
print("First Packet:")
print(packets[0].summary())