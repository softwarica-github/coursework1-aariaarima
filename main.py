import scapy.all as scapy


def sniffer(packet):
	if scapy.TCP in packet:
		return {"Source": packet[scapy.IP].src, "Destination": packet[scapy.IP].dst,
				"SPort": str(packet[scapy.IP].sport), "DPort": str(packet[scapy.IP].dport),
				"Payload": str(packet[scapy.TCP].payload) if packet[scapy.TCP].payload else None,
				"ActualPayload": scapy.bytes_hex(packet[scapy.TCP].payload).decode() if packet[scapy.TCP].payload else None}


def packet_sniffer():
	return sniffer(scapy.sniff(count=1)[0])


def packet_decoding(hex_data):
	return str(scapy.hex_bytes(hex_data))


def is_hex(data):
	try:
		int(data, 16)
		return True
	except ValueError:
		return False


def packet_manipulation(packet):
	try:
		scapy.send(scapy.IP(src=packet[0], dst=packet[1])/scapy.TCP(sport=packet[2], dport=packet[3])/scapy.Raw(
			load=scapy.hex_bytes(packet[4]) if is_hex(packet[4]) is True else packet[4]))
		return True
	except KeyError:
		return False
	