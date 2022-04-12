#!/usr/bin/env python3
import socket
from argparse import ArgumentParser
from multiprocessing import Pool
from re import match
from struct import error, unpack

dns_transaction_id = b'\x02\x28'

dns_payload = dns_transaction_id + \
    b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + \
    b'\x02\x65\x31\x02\x72\x75\x00\x00\x01\x00\x01'


def sntp_match(data):
    try:
        unpack('!BBBb11I', data)
        return True
    except error:
        return False


proto_signatures = {
    'DNS': lambda data: data.startswith(dns_transaction_id),
    'HTTP': lambda data: b'HTTP/' in data,
    'POP3': lambda data: data.startswith(b'+'),
    'SMTP': lambda data: match(b'[0-9]{3}', data[:3]),
    'SNTP': sntp_match
}


class Scanner:
    def __init__(self, host, timeout):
        self._host = host
        self._timeout = timeout / 1000

    def tcp(self, port):
        tcp_proto_payloads = (
            ('HTTP', b"GET aboba/\n\n"),
            ('SMTP', b'EHLO'),
            ('DNS', b'\x00\x17' + dns_payload),
            ('POP3', b'AUTH')
        )

        socket.setdefaulttimeout(self._timeout)
        for proto, payload in tcp_proto_payloads:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
                try:
                    tcp.connect((self._host, port))
                except (socket.timeout, ConnectionRefusedError):
                    return port, None
                try:
                    tcp.send(payload)
                    out = tcp.recv(128)
                    if proto == 'DNS':
                        out = out[2:]
                    if proto_signatures[proto](out):
                        return port, proto
                except (socket.error, OSError):
                    continue
        return port, 'Unknown'

    def udp(self, port):
        socket.setdefaulttimeout(self._timeout)
        if not self._udp_is_open(port):
            return port, None
        return port, self._udp_determine_proto(port)

    def _udp_is_open(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            with socket.socket(
                    socket.AF_INET,
                    socket.SOCK_RAW,
                    socket.IPPROTO_ICMP) as icmp:
                try:
                    udp.sendto(b"whassup dude", (self._host, port))
                    icmp.recvfrom(1024)
                    return False
                except socket.timeout:
                    pass
                except (socket.error, OSError):
                    return False
            return True

    def _udp_determine_proto(self, port):
        udp_proto_payloads = (
            ('SNTP', b'\x1b' + 47 * b'\0'),
            ('DNS', dns_payload)
        )

        for proto, payload in udp_proto_payloads:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                try:
                    udp.sendto(payload, (self._host, port))
                    out = udp.recv(128)
                    if proto_signatures[proto](out):
                        return proto
                except (socket.error, OSError):
                    continue
        return "Unknown"


def main():
    parser = ArgumentParser(
        description='My nmap copycat (TCP UDP port scanner)')
    parser.add_argument('host', type=str,
                        help='Destination address or domain name')
    parser.add_argument('-tcp', action='store_true', help='Scan TCP ports')
    parser.add_argument('-udp', action='store_true', help='Scan UDP ports')
    parser.add_argument('-s', '--start_port', type=int, default=1,
                        help='Start port to scan')
    parser.add_argument('-e', '--end_port', type=int, default=1024,
                        help='End port to scan')
    parser.add_argument('-t', '--timeout', type=int, default=150,
                        help='Response timeout in milliseconds')
    parser.add_argument('-p', '--processes', type=int, default=4,
                        help='Simultaneous processes count')

    args = parser.parse_args()
    if not (args.tcp or args.udp):
        args.tcp = args.udp = True

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        return print(f"Unable to resolve name: {args.host}")

    if not ip:
        return print("Invalid IP specified")

    print(f"Scanning {args.host} {'' if ip == args.host else f'({ip})'}..")

    pool = Pool(args.processes)
    scanner = Scanner(ip, args.timeout)

    if args.tcp:
        scan = pool.map(scanner.tcp, range(
            args.start_port, args.end_port + 1))
        for port, proto in scan:
            if proto:
                print(f'Open {port}/tcp, proto: {proto}')
    if args.udp:
        scan = map(scanner.udp, range(
            args.start_port, args.end_port + 1))
        for port, proto in scan:
            if proto:
                print(f'Open {port}/udp, proto: {proto}')


if __name__ == "__main__":
    main()
