import argparse
import logging
import random
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# Глушим лишние предупреждения scapy, чтобы не получить штраф -2 за мусор в выводе
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import ICMP, IP, TCP, UDP, conf, send, sr1  # noqa: E402

conf.verb = 0  # Запрещаем scapy печатать служебные сообщения (типа "Sent 1 packets")

# Блокировка, чтобы потоки не перемешивали текст при одновременном print()
print_lock = threading.Lock()


# ==========================================
# 1. РАЗБОР АРГУМЕНТОВ И ПОРТОВ
# ==========================================

def parse_targets(target_args: list[str]) -> list[tuple[str, int]]:
    """
    Превращает аргументы вида ['tcp/80,443', 'udp/50-53']
    в плоский список пар: [('TCP', 80), ('TCP', 443), ('UDP', 50), ...]
    """
    tasks: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()

    for item in target_args:
        parts = item.split("/", 1)
        proto = parts[0].upper()

        if proto not in ("TCP", "UDP"):
            raise ValueError(f"Неизвестный протокол: {proto}")

        # Если порты не указаны (просто 'tcp' или 'udp') — берём все порты
        if len(parts) == 1 or not parts[1]:
            ports = range(1, 65536)
        else:
            ports = []
            for chunk in parts[1].split(","):
                if "-" in chunk:
                    start_str, end_str = chunk.split("-", 1)
                    start, end = int(start_str), int(end_str)
                    if not (1 <= start <= end <= 65535):
                        raise ValueError(f"Неверный диапазон портов: {chunk}")
                    ports.extend(range(start, end + 1))
                else:
                    port = int(chunk)
                    if not (1 <= port <= 65535):
                        raise ValueError(f"Неверный порт: {chunk}")
                    ports.append(port)

        for port in ports:
            key = (proto, port)
            if key not in seen:
                seen.add(key)
                tasks.append(key)

    return tasks


# ==========================================
# 2. СКАНИРОВАНИЕ ПОРТОВ (TCP SYN и UDP)
# ==========================================

def scan_tcp_syn(ip: str, port: int, timeout: float) -> tuple[bool, float | None]:
    """
    Отправляет TCP SYN через scapy.
    Если пришёл SYN-ACK — порт открыт, сразу шлём RST (чтобы закрыть полуоткрытое соединение).
    Возвращает: (открыт_ли_порт, время_ответа_в_мс).
    """
    src_port = random.randint(1024, 65535)
    syn_pkt = IP(dst=ip) / TCP(sport=src_port, dport=port, flags="S")

    start_time = time.perf_counter()
    resp = sr1(syn_pkt, timeout=timeout, verbose=0)
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    if resp is None:
        return False, None

    if resp.haslayer(TCP):
        flags = resp[TCP].flags
        # 0x12 означает SYN + ACK ("SA") — порт открыт!
        if flags == 0x12:
            # ОБЯЗАТЕЛЬНО шлём RST, чтобы не получить штраф -2 за полуоткрытое соединение
            rst_pkt = IP(dst=ip) / TCP(
                sport=src_port,
                dport=port,
                seq=resp[TCP].ack,
                flags="R",
            )
            send(rst_pkt, verbose=0)
            return True, elapsed_ms

    return False, None


def scan_udp(ip: str, port: int, timeout: float) -> bool:
    """
    Отправляет пустой UDP-пакет.
    - Пришёл ICMP Port Unreachable (type=3, code=3) -> порт закрыт.
    - Пришёл UDP-ответ или тишина (таймаут) -> считаем порт открытым.
    """
    pkt = IP(dst=ip) / UDP(dport=port)
    resp = sr1(pkt, timeout=timeout, verbose=0)

    if resp is None:
        # Тишина в UDP обычно означает, что порт открыт (или фильтруется)
        return True

    if resp.haslayer(UDP):
        # Программа на той стороне ответила — порт точно открыт
        return True

    if resp.haslayer(ICMP):
        # Type 3 (Destination Unreachable), коды 1,2,3,9,10,13 означают закрыт/недоступен
        if resp[ICMP].type == 3 and resp[ICMP].code in (1, 2, 3, 9, 10, 13):
            return False

    return False


# ==========================================
# 3. ОПРЕДЕЛЕНИЕ ПРОТОКОЛА (-g / --guess)
# ==========================================

# Готовый минимальный DNS-запрос для домена "example.com" с ID = 0xAABB
DNS_QUERY = (
    b"\xaa\xbb"  # Transaction ID
    b"\x01\x00"  # Флаги: стандартный запрос
    b"\x00\x01"  # 1 вопрос
    b"\x00\x00\x00\x00\x00\x00"  # 0 ответов/записей
    b"\x07example\x03com\x00"  # Имя домена
    b"\x00\x01"  # Тип A (IPv4)
    b"\x00\x01"  # Класс IN (Internet)
)


def is_http(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
            sock.sendall(req)
            data = sock.recv(64)
            return data.startswith(b"HTTP/")
    except OSError:
        return False


def is_dns(ip: str, port: int, proto: str, timeout: float) -> bool:
    try:
        if proto == "UDP":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(DNS_QUERY, (ip, port))
                data, _ = sock.recvfrom(512)
        else:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                # В DNS поверх TCP перед пакетом идут 2 байта с его длиной
                sock.sendall(struct.pack("!H", len(DNS_QUERY)) + DNS_QUERY)
                raw_len = sock.recv(2)
                if len(raw_len) < 2:
                    return False
                resp_len = struct.unpack("!H", raw_len)[0]
                data = sock.recv(resp_len)

        # Проверяем: совпал ли ID (0xAABB) и выставлен ли бит "это ответ" (0x80)
        return len(data) >= 12 and data[:2] == b"\xaa\xbb" and (data[2] & 0x80) != 0
    except OSError:
        return False


def is_echo(ip: str, port: int, proto: str, timeout: float) -> bool:
    payload = b"portscan_echo_probe_12345\r\n"
    try:
        if proto == "UDP":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(payload, (ip, port))
                data, _ = sock.recvfrom(1024)
        else:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(payload)
                data = sock.recv(1024)

        return data == payload
    except OSError:
        return False


def guess_protocol(ip: str, port: int, proto: str, timeout: float) -> str:
    if proto == "TCP":
        if is_http(ip, port, timeout):
            return "HTTP"
        if is_dns(ip, port, "TCP", timeout):
            return "DNS"
        if is_echo(ip, port, "TCP", timeout):
            return "ECHO"
    else:
        if is_dns(ip, port, "UDP", timeout):
            return "DNS"
        if is_echo(ip, port, "UDP", timeout):
            return "ECHO"
    return "-"


# ==========================================
# 4. РАБОТА ОДНОГО ПОТОКА И ЗАПУСК
# ==========================================

def worker(ip: str, proto: str, port: int, timeout: float, verbose: bool, guess: bool) -> None:
    if proto == "TCP":
        is_open, rtt_ms = scan_tcp_syn(ip, port, timeout)
    else:
        is_open = scan_udp(ip, port, timeout)
        rtt_ms = None

    if not is_open:
        return

    # Собираем строку вывода строго по формату: TCP|UDP PORT [TIME,ms] [PROTOCOL|-]
    output_parts = [proto, str(port)]

    if verbose:
        if proto == "TCP" and rtt_ms is not None:
            output_parts.append(f"{rtt_ms:.2f}")
        else:
            output_parts.append("-")

    if guess:
        protocol_name = guess_protocol(ip, port, proto, timeout)
        output_parts.append(protocol_name)

    with print_lock:
        print(" ".join(output_parts), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="portscan",
        description="TCP/UDP сканер портов",
    )
    parser.add_argument("--timeout", type=float, default=2.0, help="Таймаут ожидания ответа в секундах")
    parser.add_argument("-j", "--num-threads", type=int, default=20, help="Число потоков")
    parser.add_argument("-v", "--verbose", action="store_true", help="Подробный режим (время ответа для TCP)")
    parser.add_argument("-g", "--guess", action="store_true", help="Определение протокола (HTTP, DNS, ECHO)")
    parser.add_argument("ip", metavar="IP_ADDRESS", help="Целевой IP-адрес")
    parser.add_argument("targets", nargs="+", help="Спецификация портов (например, tcp/80,443 udp/53)")

    # parse_intermixed_args позволяет писать флаги в любом месте (и до IP, и после)
    args = parser.parse_intermixed_args()

    try:
        tasks = parse_targets(args.targets)
    except ValueError as err:
        print(f"Ошибка в аргументах: {err}", file=sys.stderr)
        sys.exit(1)

    with ThreadPoolExecutor(max_workers=args.num_threads) as executor:
        for proto, port in tasks:
            executor.submit(
                worker,
                args.ip,
                proto,
                port,
                args.timeout,
                args.verbose,
                args.guess,
            )


if __name__ == "__main__":
    main()