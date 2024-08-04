import scapy.all as scapy

def sniff_packets(interface):
  """Sniffs packets on the specified interface and prints information.

  Args:
    interface: The network interface to capture packets from.
  """

  scapy.sniff(iface=interface, store=False, prn=lambda packet: analyze_packet(packet))

def analyze_packet(packet):
  """Analyzes the captured packet and prints relevant information.

  Args:
    packet: The captured packet.
  """

  # Check for IP layer
  if packet.haslayer(scapy.IP):
    ip_header = packet[scapy.IP]
    src_ip = ip_header[scapy.IP].src
    dst_ip = ip_header[scapy.IP].dst
    protocol = ip_header[scapy.IP].proto

    # Print information
    print(f"Source: {src_ip}, Destination: {dst_ip}, Protocol: {protocol}")

    # Extract payload if desired
    if packet.haslayer(scapy.Raw):
      payload = packet[scapy.Raw].load
      print(f"Payload: {payload}")

if __name__ == "__main__":
  interface = "your_interface_name"  # Replace with your interface name
  sniff_packets(interface)
