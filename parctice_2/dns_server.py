import asyncio
import json
import os
import random
import socket
import struct
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Корневые серверы (a.root-servers.net, b.root-servers.net, и т.д.)
ROOT_SERVERS = [
    "198.41.0.4",
    "170.247.170.2",
    "192.33.4.12",
    "199.7.91.13",
]

CACHE_FILE = "dns_cache.pkl"

# Коды типов записей
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28

CLASS_IN = 1


@dataclass
class DNSQuestion:
    qname: str
    qtype: int
    qclass: int


@dataclass
class DNSRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes  # Сырые байты (для неизвестных записей) или пересобранные без сжатия
    parsed_data: Optional[str] = None  # Человекочитаемое значение (IP или домен)


@dataclass
class DNSPacket:
    tx_id: int
    flags: int
    questions: List[DNSQuestion]
    answers: List[DNSRecord]
    authorities: List[DNSRecord]
    additionals: List[DNSRecord]

    @property
    def rcode(self) -> int:
        return self.flags & 0x000F


# =====================================================================
# 1. Ручной парсинг и сборка протокола DNS (20 баллов + 2 балла за типы)
# =====================================================================

def encode_domain_name(domain: str) -> bytes:
    """Кодирует доменное имя в формат DNS (3www7example3com0)."""
    domain = domain.strip(".")
    if not domain:
        return b"\x00"
    parts = domain.split(".")
    return b"".join(len(p).to_bytes(1, "big") + p.encode("ascii") for p in parts) + b"\x00"


def decode_domain_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Декодирует доменное имя с учетом DNS pointer compression (0xC0)."""
    labels = []
    jumped = False
    original_offset = offset
    max_jumps = 20
    jumps = 0

    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # Проверка на указатель сжатия (первые два бита 11 -> 0xC0)
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
                jumped = True
            pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
            offset = pointer
            jumps += 1
            if jumps > max_jumps:
                raise ValueError("Слишком много переходов сжатия в DNS-пакете")
        else:
            offset += 1
            labels.append(data[offset : offset + length].decode("ascii", errors="ignore"))
            offset += length

    domain = ".".join(labels).lower()
    return domain, (original_offset if jumped else offset)


def parse_record(data: bytes, offset: int) -> Tuple[DNSRecord, int]:
    """Парсит одну Resource Record (RR) и распаковывает сжатые имена внутри RDATA."""
    name, offset = decode_domain_name(data, offset)
    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
    offset += 10
    rdata_start = offset
    raw_rdata = data[offset : offset + rdlength]
    offset += rdlength

    parsed_data = None
    uncompressed_rdata = raw_rdata

    # Распаковываем сжатые домены внутри RDATA, чтобы при отправке клиенту
    # или сохранении в кеш не ломались смещения (pointers)!
    if rtype == TYPE_A and rdlength == 4:
        parsed_data = socket.inet_ntop(socket.AF_INET, raw_rdata)
    elif rtype == TYPE_AAAA and rdlength == 16:
        parsed_data = socket.inet_ntop(socket.AF_INET6, raw_rdata)
    elif rtype in (TYPE_NS, TYPE_CNAME):
        target_domain, _ = decode_domain_name(data, rdata_start)
        parsed_data = target_domain
        uncompressed_rdata = encode_domain_name(target_domain)
    elif rtype == TYPE_MX:
        preference = struct.unpack("!H", raw_rdata[:2])[0]
        exchange, _ = decode_domain_name(data, rdata_start + 2)
        parsed_data = f"{preference} {exchange}"
        uncompressed_rdata = struct.pack("!H", preference) + encode_domain_name(exchange)
    elif rtype == TYPE_SOA:
        mname, next_off = decode_domain_name(data, rdata_start)
        rname, next_off = decode_domain_name(data, next_off)
        tail = data[next_off : rdata_start + rdlength]
        uncompressed_rdata = encode_domain_name(mname) + encode_domain_name(rname) + tail

    return DNSRecord(name, rtype, rclass, ttl, uncompressed_rdata, parsed_data), offset


def parse_packet(data: bytes) -> DNSPacket:
    """Полный разбор сырого DNS-пакета."""
    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!6H", data[:12])
    offset = 12

    questions = []
    for _ in range(qdcount):
        qname, offset = decode_domain_name(data, offset)
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        questions.append(DNSQuestion(qname, qtype, qclass))

    answers, authorities, additionals = [], [], []
    for _ in range(ancount):
        rec, offset = parse_record(data, offset)
        answers.append(rec)
    for _ in range(nscount):
        rec, offset = parse_record(data, offset)
        authorities.append(rec)
    for _ in range(arcount):
        rec, offset = parse_record(data, offset)
        additionals.append(rec)

    return DNSPacket(tx_id, flags, questions, answers, authorities, additionals)


def build_packet(
    tx_id: int,
    flags: int,
    questions: List[DNSQuestion],
    answers: List[DNSRecord] = None,
    authorities: List[DNSRecord] = None,
    additionals: List[DNSRecord] = None,
) -> bytes:
    """Собирает DNS-пакет в байты."""
    answers = answers or []
    authorities = authorities or []
    additionals = additionals or []

    header = struct.pack(
        "!6H",
        tx_id,
        flags,
        len(questions),
        len(answers),
        len(authorities),
        len(additionals),
    )

    body = bytearray()
    for q in questions:
        body.extend(encode_domain_name(q.qname))
        body.extend(struct.pack("!HH", q.qtype, q.qclass))

    for section in (answers, authorities, additionals):
        for rec in section:
            # Пропускаем псевдо-записи OPT (EDNS0, type 41), чтобы не усложнять ответ
            if rec.rtype == 41:
                continue
            body.extend(encode_domain_name(rec.name))
            body.extend(
                struct.pack("!HHIH", rec.rtype, rec.rclass, max(0, rec.ttl), len(rec.rdata))
            )
            body.extend(rec.rdata)

    return header + bytes(body)


# =====================================================================
# 2. Кеширование с учетом TTL и сохранением на диск (3 + 1 балл)
# =====================================================================

class DNSCache:
    def __init__(self, filename: str = CACHE_FILE):
        self.filename = filename
        # Ключ: (qname, qtype) -> Значение: (rcode, List[(DNSRecord, expire_time)])
        self.store: Dict[Tuple[str, int], Tuple[int, List[Tuple[DNSRecord, float]]]] = {}
        self.load()

    def get(self, qname: str, qtype: int) -> Optional[Tuple[int, List[DNSRecord]]]:
        key = (qname.lower(), qtype)
        if key not in self.store:
            return None

        rcode, items = self.store[key]
        now = time.time()
        valid_records = []

        for rec, expire_at in items:
            remaining_ttl = int(expire_at - now)
            if remaining_ttl <= 0:
                # Если хотя бы одна запись устарела, сбрасываем ключ целиком
                del self.store[key]
                return None
            # Возвращаем копию с актуальным остатком TTL
            valid_records.append(
                DNSRecord(rec.name, rec.rtype, rec.rclass, remaining_ttl, rec.rdata, rec.parsed_data)
            )

        return rcode, valid_records

    def put(self, qname: str, qtype: int, rcode: int, records: List[DNSRecord], default_ttl: int = 60):
        now = time.time()
        items = []
        if records:
            for rec in records:
                ttl = rec.ttl if rec.ttl > 0 else default_ttl
                items.append((rec, now + ttl))
        else:
            # Для NXDOMAIN или пустого ответа сохраняем пустой список с коротким TTL
            items.append((DNSRecord(qname, qtype, CLASS_IN, default_ttl, b""), now + default_ttl))

        self.store[(qname.lower(), qtype)] = (rcode, items)
        self.save()

    def save(self):
        try:
            serializable = {}
            now = time.time()
            for (qname, qtype), (rcode, items) in self.store.items():
                if all(exp > now for _, exp in items):
                    serializable[f"{qname}|{qtype}"] = {
                        "rcode": rcode,
                        "items": [
                            {
                                "name": r.name,
                                "rtype": r.rtype,
                                "rclass": r.rclass,
                                "ttl": r.ttl,
                                "rdata": r.rdata.hex(),
                                "parsed_data": r.parsed_data,
                                "exp": exp,
                            }
                            for r, exp in items
                        ],
                    }
            with open(self.filename, "w", encoding="utf-8") as f:
                json.dump(serializable, f)
        except Exception as e:
            print(f"[WARN] Ошибка сохранения кеша: {e}")

    def load(self):
        if not os.path.exists(self.filename):
            return
        try:
            with open(self.filename, "r", encoding="utf-8") as f:
                data = json.load(f)
            now = time.time()
            for k, val in data.items():
                qname, qtype_str = k.rsplit("|", 1)
                qtype = int(qtype_str)
                rcode = val["rcode"]
                items = []
                for item in val["items"]:
                    if item["exp"] > now:
                        rec = DNSRecord(
                            name=item["name"],
                            rtype=item["rtype"],
                            rclass=item["rclass"],
                            ttl=item["ttl"],
                            rdata=bytes.fromhex(item["rdata"]),
                            parsed_data=item["parsed_data"],
                        )
                        items.append((rec, item["exp"]))
                if items:
                    self.store[(qname, qtype)] = (rcode, items)
            print(f"[INFO] Загружено записей из кеша: {len(self.store)}")
        except Exception as e:
            print(f"[WARN] Не удалось загрузить кеш: {e}")


# =====================================================================
# 3. Специальное правило .multiply. (3 балла)
# =====================================================================

def check_multiply_rule(qname: str, qtype: int) -> Optional[List[DNSRecord]]:
    """
    Если в запросе встречается '.multiply.', возвращает IP 127.0.0.X,
    где X - произведение чисел до 'multiply' по модулю 256.
    Пример: 2.22.multiply.test.com -> 127.0.0.44
    """
    clean_name = qname.strip(".").lower()
    labels = clean_name.split(".")
    if "multiply" not in labels:
        return None

    idx = labels.index("multiply")
    prefix_labels = labels[:idx]

    if not prefix_labels:
        return None

    product = 1
    try:
        for lbl in prefix_labels:
            product = (product * int(lbl)) % 256
    except ValueError:
        # Если до multiply встретилось не число — правило не срабатывает (или можно вернуть 0)
        return None

    if qtype != TYPE_A:
        # Если спросили AAAA или TXT для .multiply., возвращаем пустой NOERROR
        return []

    ip_str = f"127.0.0.{product}"
    rdata = socket.inet_pton(socket.AF_INET, ip_str)
    return [DNSRecord(clean_name, TYPE_A, CLASS_IN, 300, rdata, ip_str)]


# =====================================================================
# 4. Итеративный резолвер (База)
# =====================================================================

async def send_udp_query(server_ip: str, packet_bytes: bytes, timeout: float = 2.5) -> Optional[bytes]:
    """Отправляет одиночный UDP-запрос к авторитетному серверу."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_sendto(sock, packet_bytes, (server_ip, 53))
        data = await asyncio.wait_for(loop.sock_recv(sock, 4096), timeout=timeout)
        return data
    except Exception:
        return None
    finally:
        sock.close()


class IterativeResolver:
    def __init__(self, cache: DNSCache):
        self.cache = cache

    async def resolve(self, qname: str, qtype: int, depth: int = 0) -> Tuple[int, List[DNSRecord]]:
        """
        Возвращает кортеж (RCODE, список ответов DNSRecord).
        RCODE: 0 = NOERROR, 3 = NXDOMAIN, 2 = SERVFAIL
        """
        qname = qname.strip(".").lower()

        if depth > 15:
            return 2, []  # Защита от бесконечной рекурсии CNAME/NS

        # 1. Проверяем спецправило .multiply.
        mult_res = check_multiply_rule(qname, qtype)
        if mult_res is not None:
            print(f"[MULTIPLY] {qname} -> {mult_res[0].parsed_data if mult_res else 'EMPTY'}")
            return 0, mult_res

        # 2. Проверяем кеш
        cached = self.cache.get(qname, qtype)
        if cached is not None:
            rcode, records = cached
            # Для пустых/NXDOMAIN записей у нас лежит заглушка с пустым rdata
            if records and len(records) == 1 and records[0].rdata == b"":
                return rcode, []
            print(f"[CACHE HIT] {qname} (type={qtype})")
            return rcode, records

        # 3. Итеративный опрос начиная с корневых серверов
        nameservers = list(ROOT_SERVERS)
        random.shuffle(nameservers)

        for _step in range(20):
            if not nameservers:
                break

            tx_id = random.randint(1, 65534)
            # Флаг 0x0000: стандартный запрос БЕЗ рекурсии (RD=0)
            query_pkt = build_packet(tx_id, 0x0000, [DNSQuestion(qname, qtype, CLASS_IN)])

            response_pkt = None
            for ns_ip in nameservers:
                raw_resp = await send_udp_query(ns_ip, query_pkt)
                if raw_resp:
                    try:
                        response_pkt = parse_packet(raw_resp)
                        break
                    except Exception:
                        continue

            if not response_pkt:
                break

            # Если домен не существует (NXDOMAIN = 3)
            if response_pkt.rcode == 3:
                self.cache.put(qname, qtype, 3, [])
                return 3, []

            # Попутно кешируем A-записи из Additional (Glue records)
            for add_rec in response_pkt.additionals:
                if add_rec.rtype == TYPE_A and add_rec.parsed_data:
                    self.cache.put(add_rec.name, TYPE_A, 0, [add_rec])

            # Случай А: Есть ответы в секции Answer
            if response_pkt.answers:
                # Проверяем, есть ли прямой ответ нужного типа
                direct_answers = [r for r in response_pkt.answers if r.rtype == qtype]
                if direct_answers:
                    self.cache.put(qname, qtype, 0, response_pkt.answers)
                    return 0, response_pkt.answers

                # Если мы искали A/AAAA/TXT, а нам вернули только CNAME — нужно доразрешить CNAME!
                cnames = [r for r in response_pkt.answers if r.rtype == TYPE_CNAME]
                if cnames and qtype != TYPE_CNAME:
                    cname_rec = cnames[0]
                    target_domain = cname_rec.parsed_data
                    rcode, target_records = await self.resolve(target_domain, qtype, depth + 1)
                    combined = [cname_rec] + target_records
                    if rcode == 0:
                        self.cache.put(qname, qtype, 0, combined)
                    return rcode, combined

                self.cache.put(qname, qtype, 0, response_pkt.answers)
                return 0, response_pkt.answers

            # Случай Б: В Authority вернулся SOA (значит домен есть, но записей такого типа нет -> NODATA)
            if any(r.rtype == TYPE_SOA for r in response_pkt.authorities):
                self.cache.put(qname, qtype, 0, [])
                return 0, []

            # Случай В: Делегирование (список NS-серверов в секции Authority)
            ns_records = [r for r in response_pkt.authorities if r.rtype == TYPE_NS and r.parsed_data]
            if not ns_records:
                return 0, []

            # Ищем IP-адреса для этих NS в секции Additional (Glue records)
            glue_ips = {}
            for add_rec in response_pkt.additionals:
                if add_rec.rtype == TYPE_A and add_rec.parsed_data:
                    glue_ips[add_rec.name.lower()] = add_rec.parsed_data

            next_nameservers = []
            for ns_rec in ns_records:
                ns_domain = ns_rec.parsed_data.lower()
                if ns_domain in glue_ips:
                    next_nameservers.append(glue_ips[ns_domain])

            # Если Glue records нет (например, NS в другой зоне), резолвим IP первого NS-сервера!
            if not next_nameservers:
                for ns_rec in ns_records[:2]:
                    ns_domain = ns_rec.parsed_data.lower()
                    rcode, ns_a_records = await self.resolve(ns_domain, TYPE_A, depth + 1)
                    for r in ns_a_records:
                        if r.rtype == TYPE_A and r.parsed_data:
                            next_nameservers.append(r.parsed_data)
                    if next_nameservers:
                        break

            nameservers = next_nameservers

        # Если ничего не вышло — возвращаем пустой NOERROR, чтобы сервер никогда не падал
        return 0, []


# =====================================================================
# 5. Обработка клиентских запросов по UDP и TCP (3 + 2 балла)
# =====================================================================

async def handle_dns_query(raw_data: bytes, resolver: IterativeResolver) -> bytes:
    """Формирует корректный ответ клиенту и гарантирует отсутствие падений."""
    try:
        req = parse_packet(raw_data)
        if not req.questions:
            return build_packet(req.tx_id, 0x8180, [])

        q = req.questions[0]
        print(f"[QUERY] {q.qname} (type={q.qtype})")

        rcode, answers = await resolver.resolve(q.qname, q.qtype)

        # Формируем флаги ответа:
        # QR = 1 (ответ), RD = копируем из запроса, RA = 1 (рекурсия доступна), RCODE = 0 или 3
        rd_bit = req.flags & 0x0100
        resp_flags = 0x8000 | rd_bit | 0x0080 | (rcode & 0x000F)

        return build_packet(req.tx_id, resp_flags, req.questions, answers=answers)

    except Exception as e:
        print(f"[ERROR] Ошибка обработки пакета: {e}")
        # Даже при битом пакете стараемся вернуть NOERROR, если можем вытащить ID
        tx_id = struct.unpack("!H", raw_data[:2])[0] if len(raw_data) >= 2 else 0
        return build_packet(tx_id, 0x8180, [])


class UDPServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, resolver: IterativeResolver):
        self.resolver = resolver
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        # Запускаем обработку каждого клиента в отдельной корутине (одновременная работа!)
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data: bytes, addr: Tuple[str, int]):
        resp = await handle_dns_query(data, self.resolver)
        if self.transport:
            self.transport.sendto(resp, addr)


async def handle_tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, resolver: IterativeResolver):
    """Обработчик TCP-соединений (в TCP перед пакетом идут 2 байта длины)."""
    try:
        while True:
            length_bytes = await reader.readexactly(2)
            length = struct.unpack("!H", length_bytes)[0]
            data = await reader.readexactly(length)
            resp = await handle_dns_query(data, resolver)
            writer.write(struct.pack("!H", len(resp)) + resp)
            await writer.drain()
    except asyncio.IncompleteReadError:
        pass
    except Exception as e:
        print(f"[TCP ERROR] {e}")
    finally:
        writer.close()
        await writer.wait_closed()


async def main(host: str = "127.0.0.1", port: int = 53):
    cache = DNSCache()
    resolver = IterativeResolver(cache)
    loop = asyncio.get_running_loop()

    # Запуск UDP-сервера
    udp_transport, _ = await loop.create_datagram_endpoint(
        lambda: UDPServerProtocol(resolver), local_addr=(host, port)
    )

    # Запуск TCP-сервера
    tcp_server = await asyncio.start_server(
        lambda r, w: handle_tcp_client(r, w, resolver), host, port
    )

    print(f"[START] DNS-сервер запущен на {host}:{port} (UDP и TCP). Нажми Ctrl+C для выхода.")
    try:
        async with tcp_server:
            await tcp_server.serve_forever()
    finally:
        udp_transport.close()
        cache.save()


if __name__ == "__main__":
    try:
        asyncio.run(main("127.0.0.1", 53))
    except PermissionError:
        print("Ошибка прав доступа к порту 53! Запусти с sudo (Linux/macOS) или от имени Администратора (Windows).")
    except KeyboardInterrupt:
        print("\n[STOP] Сервер остановлен.")