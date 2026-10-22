import socket
import re

def send_wake_on_lan(mac_address, broadcast_ip="255.255.255.255", port=9):
    """
    Sends a Wake-on-LAN (WOL) magic packet to awaken a target device.
    """
    clean_mac = re.sub(r'[^a-fA-F0-9]', '', mac_address)
    if len(clean_mac) != 12:
        raise ValueError(f"Endereço MAC inválido: {mac_address}")

    # Build 102-byte Magic Packet: 6 bytes of 0xFF followed by 16 repetitions of MAC
    mac_bytes = bytes.fromhex(clean_mac)
    magic_packet = b'\xff' * 6 + mac_bytes * 16

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto(magic_packet, (broadcast_ip, port))
    sock.close()
    return True
