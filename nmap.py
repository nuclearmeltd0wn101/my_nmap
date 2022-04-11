#!/usr/bin/env python3
import socket
from argparse import ArgumentParser
from multiprocessing import Pool
from re import match
from struct import pack, unpack

DNS_TRANSACTION_ID = b'\x02\x28'

DNS_PAYLOAD = DNS_TRANSACTION_ID + \
    b'\x01\x00\x00\x01' + \
    b'\x00\x00\x00\x00\x00\x00' + \
    b'\x02\x65\x31\x02\x72\x75' + \
    b'\x00\x00\x01\x00\x01'

TCP_PROTO_PAYLOADS = {
    'HTTP': b"GET aboba/\n\n",
    'SMTP': b'EHLO',
    'DNS': DNS_PAYLOAD,
    'POP3': b'AUTH'
}

UDP_PROTO_PAYLOADS = {
    'SNTP': b'\x1b' + 47 * b'\0',
    'DNS': DNS_PAYLOAD
}

PROTO_SIGNATURES = {
    'HTTP': lambda packet: b'HTTP/' in packet,
    'POP3': lambda packet: packet.startswith(b'+'),
    'DNS': lambda packet: packet.startswith(DNS_TRANSACTION_ID),
    'SMTP': lambda packet: match(b'[0-9]{3}', packet[:3]),
    'SNTP': lambda packet: sntp_check(packet)
}


def sntp_check(packet):
    try:
        unpack('!BBBb11I', packet)
        return True
    except Exception:
        return False


class Scanner:
    def __init__(self, host, timeout):
        self._host = host
        self._timeout = timeout / 1000

    def tcp(self, port):
        socket.setdefaulttimeout(self._timeout)
        for proto, packet in TCP_PROTO_PAYLOADS.items():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.connect((self._host, port))
                except (socket.timeout, ConnectionRefusedError):
                    return port, None
                try:
                    if proto == 'DNS':
                        packet = pack('!H', len(packet)) + packet

                    s.send(packet)
                    packet = s.recv(128)
                    if proto == 'DNS':
                        packet = packet[2:]
                    if PROTO_SIGNATURES[proto](packet):
                        return port, proto
                except (socket.error, OSError):
                    continue
        return port, 'Unknown'

    def udp(self, port):
        socket.setdefaulttimeout(self._timeout)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for proto, packet in UDP_PROTO_PAYLOADS.items():
                try:
                    s.sendto(packet, (self._host, port))
                    if PROTO_SIGNATURES[proto](s.recv(128)):
                        return port, proto
                except (socket.error, OSError):
                    continue
        return port, None


def main():
    parser = ArgumentParser(
        description='My nmap copycat (TCP UDP port scanner)')
    parser.add_argument('host', type=str,
                        help='Destination address or domain name')
    parser.add_argument('-tcp', action='store_true', help='Scan TCP ports')
    parser.add_argument('-udp', action='store_true', help='Scan UDP ports')
    parser.add_argument('-s', '--start_port', default=1,
                        type=int, help='Start port to scan')
    parser.add_argument('-e', '--end_port', default=1024,
                        type=int, help='End port to scan')
    parser.add_argument('-t', '--timeout', default=100,
                        type=int, help='Response timeout in milliseconds')
    parser.add_argument('-p', '--processes', default=4,
                        type=int, help='Simultaneous processes count')

    args = parser.parse_args()
    if not (args.tcp or args.udp):
        args.tcp = args.udp = True

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        return print(f"Unable to resolve name: {args.host}")

    if not ip:
        return print("Invalid IP specified")

    pool = Pool(args.processes)
    scanner = Scanner(ip, args.timeout)

    if args.tcp:
        scan = pool.map(scanner.tcp, range(
            args.start_port, args.end_port + 1))
        for port, proto in scan:
            if proto:
                print(f'Open TCP {port}, proto: {proto}')
    if args.udp:
        scan = pool.map(scanner.udp, range(
            args.start_port, args.end_port + 1))
        for port, proto in scan:
            if proto:
                print(f'Open UDP {port}, proto: {proto}')


if __name__ == "__main__":
    main()
