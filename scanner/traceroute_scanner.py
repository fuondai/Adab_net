import socket
import sys
from colorama import Fore, Style

def tracert(host, maxhops=30, timeout=1.0):  # Tăng timeout từ 0.2 lên 1.0 giây
    """
    Traceroute function to trace the path packets take to the target host.

    :param host: The target hostname or IP address.
    :param maxhops: Maximum number of hops to trace (default: 30).
    :param timeout: Timeout for each hop (default: 1.0 seconds).
    :return: A list of IP addresses of each hop.
    """
    proto_icmp = socket.getprotobyname('icmp')
    proto_udp = socket.getprotobyname('udp')
    host_addr = socket.gethostbyname(host)
    port = 33434
    result = []

    for ttl in range(1, maxhops):
        try:
            # Create a raw socket for receiving the reply
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, proto_icmp) as rx:
                rx.settimeout(timeout)
                rx.bind(('', port))

                # Create a UDP socket for sending the packet
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto_udp) as tx:
                    tx.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                    tx.sendto(b'', (host_addr, port))

                    try:
                        # Receive the reply from the router
                        data, curr_addr = rx.recvfrom(512)
                        curr_addr = curr_addr[0]
                    except socket.timeout:  # Catch specific timeout error
                        curr_addr = None

                result.append(curr_addr)

                if curr_addr == host_addr:
                    break

        except socket.error as e:
            print(f"[{Fore.RED}!{Style.RESET_ALL}] Socket error: {e}")
            continue

    return result
