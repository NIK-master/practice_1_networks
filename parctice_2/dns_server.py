import asyncio
import json
import os
import random
import socket
import struct
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Главные dns-серваки инета
# Обратиться можно к любому так как у нас единый каталог данных там
ROOT_SERVERS = [
    "198.41.0.4",
    "170.247.170.2",
    "192.33.4.12",
    "199.7.91.13",
]

# Куда будет слкадываться кэш, чтобы не нагружать сервак
CACHE_FILE = "dns_cache.json"

# Константы
TYPE_A = 1      # IPv4-адрес
TYPE_AAAA = 28  # IPv6-адрес
TYPE_NS = 2     # Имя ответственного DNS-сервера зоны
TYPE_CNAME = 5  # Каноническое имя
TYPE_SOA = 6    # Начало зоны полномочий
TYPE_MX = 15    # Почтовый сервер
TYPE_TXT = 16   # Текстовые записи
CLASS_IN = 1    # Класс сети: Internet

# Класс вопроса днс серваку
@dataclass
class DNSQuestion:
    qname: str  # Что ищем
    qtype: int  # Тип домена, который запрашиваем
    qclass: int # Класс сети


# Класс ответа от днс-сервака
@dataclass
class DNSRecord:
    name: str                           # О каком доменном имени идёт речь
    rtype: int                          # Тип записи, которая пришла
    rclass: int                         # Класс сети записи
    ttl: int                            # Сколько эта запись будет жить айпишник в памяти
    rdata: bytes                        # Сам ответ в байтах
    parsed_data: Optional[str] = None   # Ответ в нормальном виде для логов


# Класс всего пакета для днс сервера
@dataclass
class DNSPacket:
    tx_id: int                      # ID запроса
    flags: int                      # Флаги (является ли пакет ответом, запрошена ли рекурсия, доступна ли она на сервере и т.д.)
    questions: List[DNSQuestion]    # Вопросы
    answers: List[DNSRecord]        # Ответы
    authorities: List[DNSRecord]    # Сервера, отвечающие за определенную зону
    additionals: List[DNSRecord]    # Что-то дополнительное, я не помню

    # Метод, который достаёт код ответа из флагов и переводит сразу в норм число
    @property
    def rcode(self) -> int:
        return self.flags & 0x000F



def encode_domain_name(domain: str) -> bytes:
    """Кодирует доменное имя в формат DNS (3www7example3com0)"""
    domain = domain.strip(".")
    if not domain:
        return b"\x00"
    parts = domain.split(".")
    return b"".join(len(p).to_bytes(1, "big") + p.encode("ascii") for p in parts) + b"\x00"


def decode_domain_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Декодирует доменное имя с учетом DNS pointer compression (0xC0)"""
    labels = []
    jumped = False
    original_offset = offset
    max_jumps = 20
    jumps = 0

    while True:
        if offset >= len(data):
            break
        # Читается первый байт доменного имени
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # Если первый байт - это ссылка (первый байт - 0xC0), то идем искать на что она указывает
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
                jumped = True
            # Считываем 2 байта указателя и маской 0x3FFF убираем первые две единицы от указателя-ссылки.
            pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
            offset = pointer
            jumps += 1
            # Защита от зацикливания, если вредоносный или поврежденный пакет заставит функцию прыгать по кругу
            if jumps > max_jumps:
                raise ValueError("Слишком много переходов сжатия в DNS-пакете")
        else:
            offset += 1
            # Декодируем часть домена
            labels.append(data[offset : offset + length].decode("ascii", errors="ignore"))
            offset += length

    # Собираем домен
    domain = ".".join(labels).lower()
    # Отдаем домен и еще смещение в пакете, чтобы дальше с него идти
    return domain, (original_offset if jumped else offset)


def parse_record(data: bytes, offset: int) -> Tuple[DNSRecord, int]:
    """Парсит одну Resource Record и распаковывает сжатые имена внутри RDATA."""

    # Сначала читается имя, к которому относится запись
    name, offset = decode_domain_name(data, offset)
    # Далее разбираем следующие 10 байт заголовка записи
    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
    offset += 10
    rdata_start = offset
    raw_rdata = data[offset : offset + rdlength]
    offset += rdlength

    parsed_data = None
    uncompressed_rdata = raw_rdata

    # Далее работаем в зависимости от типа записи
    if rtype == TYPE_A and rdlength == 4:
        # Для IPv4 (TYPE_A) 4 сырых байта преобразуются в IP
        parsed_data = socket.inet_ntop(socket.AF_INET, raw_rdata)
    elif rtype == TYPE_AAAA and rdlength == 16:
        # Для IPv6 (TYPE_AAAA) 16 сырых байт преобразуются в IP
        parsed_data = socket.inet_ntop(socket.AF_INET6, raw_rdata)
    elif rtype in (TYPE_NS, TYPE_CNAME):
        # Для NS (имя DNS-сервера) или CNAME (каноническое имя)
        # мы на всякий случай декодируем внутренний адрес (так как там может быть днс сжатие)
        # и обратно кодируем
        target_domain, _ = decode_domain_name(data, rdata_start)
        parsed_data = target_domain
        uncompressed_rdata = encode_domain_name(target_domain)
    elif rtype == TYPE_MX:
        # Для MX (почтового сервера) сначала идут 2 байта приоритета (preference),
        # а затем — доменное имя почтового сервера (exchange)
        preference = struct.unpack("!H", raw_rdata[:2])[0]
        exchange, _ = decode_domain_name(data, rdata_start + 2)
        # Читабельная версия - в строку
        parsed_data = f"{preference} {exchange}"
        # Для безопасного сохранения в кеш склеиваем то что брали
        uncompressed_rdata = struct.pack("!H", preference) + encode_domain_name(exchange)
    elif rtype == TYPE_SOA:
        # Запись SOA возвращается, когда мы дошли до авторитетного сервера, но нужной записи нет
        # Внутри SOA лежат сразу два доменных имени подряд:
        # mname — главный сервер зоны;
        # rname — почта администратора зоны (где @ заменена точкой)
        # И еще хвост с 4 байтами чисел
        mname, next_off = decode_domain_name(data, rdata_start)
        rname, next_off = decode_domain_name(data, next_off)
        tail = data[next_off : rdata_start + rdlength]
        # Для безопасного сохранения в кеш склеиваем то что получили
        uncompressed_rdata = encode_domain_name(mname) + encode_domain_name(rname) + tail

    return DNSRecord(name, rtype, rclass, ttl, uncompressed_rdata, parsed_data), offset


def parse_packet(data: bytes) -> DNSPacket:
    """Полный разбор сырого DNS-пакета."""

    # Чиитаем ровно первые 12 байт пакета (заголовок) как 6 двухбайтовых чисел (6H)
    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!6H", data[:12])
    offset = 12

    # Получаем вопросы
    questions = []
    for _ in range(qdcount):
        qname, offset = decode_domain_name(data, offset)
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        questions.append(DNSQuestion(qname, qtype, qclass))

    answers, authorities, additionals = [], [], []
    # Получаем ответы
    for _ in range(ancount):
        rec, offset = parse_record(data, offset)
        answers.append(rec)
    # Получаем NS записи
    for _ in range(nscount):
        rec, offset = parse_record(data, offset)
        authorities.append(rec)
    # Получаем Additional записи
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

    # Делаем заголовок
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
    # Делаем вопросы
    for q in questions:
        body.extend(encode_domain_name(q.qname))
        body.extend(struct.pack("!HH", q.qtype, q.qclass))

    # Делаем ответы
    for section in (answers, authorities, additionals):
        for rec in section:
            if rec.rtype == 41:
                continue
            body.extend(encode_domain_name(rec.name))
            body.extend(
                struct.pack("!HHIH", rec.rtype, rec.rclass, max(0, rec.ttl), len(rec.rdata))
            )
            body.extend(rec.rdata)

    return header + bytes(body)


# Класс для кэширования (учет TTL и сохранение на диск при перезапуске)
class DNSCache:
    def __init__(self, filename: str = CACHE_FILE):
        # Имя файла на диске
        self.filename = filename
        # Основной словарь в оперативной памяти:
        # Ключ словаря: кортеж (qname, qtype)
        # Значение словаря: кортеж (rcode, список пар (запись DNSRecord, TTL))
        self.store: Dict[Tuple[str, int], Tuple[int, List[Tuple[DNSRecord, float]]]] = {}
        self.load()

    # Метод поиска записи в кэше
    def get(self, qname: str, qtype: int) -> Optional[Tuple[int, List[DNSRecord]]]:
        key = (qname.lower(), qtype)
        # Ищем ключ
        if key not in self.store:
            return None
        rcode, items = self.store[key]

        # Берем время для проверки TTL
        now = time.time()
        valid_records = []

        # Проверка всего на истёкшее TTL
        for rec, expire_at in items:
            remaining_ttl = int(expire_at - now)
            # Если время вышло, запись удаляется из словаря
            if remaining_ttl <= 0:
                del self.store[key]
                return None
            # Делаем свежий DNSRecord
            valid_records.append(
                DNSRecord(rec.name, rec.rtype, rec.rclass, remaining_ttl, rec.rdata, rec.parsed_data)
            )

        return rcode, valid_records

    # Метод записи в кеш
    def put(self, qname: str, qtype: int, rcode: int, records: List[DNSRecord], default_ttl: int = 60):
        now = time.time()
        items = []
        if records:
            for rec in records:
                # Вычисляем момент времени в будущем, когда запись перестанет быть актуальной
                ttl = rec.ttl if rec.ttl > 0 else default_ttl
                items.append((rec, now + ttl))
        else:
            # Для NXDOMAIN или пустого ответа сохраняем пустой список с коротким TTL
            items.append((DNSRecord(qname, qtype, CLASS_IN, default_ttl, b""), now + default_ttl))

        self.store[(qname.lower(), qtype)] = (rcode, items)
        self.save()

    # Метод сохранения кэша на диск в .json файл
    def save(self):
        try:
            serializable = {}
            now = time.time()
            # JSON не умеет сохранять кортежи как ключи
            # и не понимает сырые байты (bytes).
            # Ключ (qname, qtype) превращается в строку: f"{qname}|{qtype}"
            # Сырые байты ответа r.rdata переводятся в шестнадцатеричную строку через hex()
            # Сделал так вместо .pkl так как .pkl труднее прочитать в блокнотах
            for (qname, qtype), (rcode, items) in self.store.items():
                # Перед сохранением отсеиваются уже протухшие записи, чтобы файл не разрастался мусором
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

    # Метод восстановления памяти сервера при перезапуске
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


# Метод специально для .multiply
def check_multiply_rule(qname: str, qtype: int) -> Optional[List[DNSRecord]]:
    """
    Если в запросе встречается '.multiply.', возвращает IP 127.0.0.X,
    где X - произведение чисел до 'multiply' по модулю 256.
    Пример: 2.22.multiply.test.com -> 127.0.0.44
    """

    # Ищем multiply
    clean_name = qname.strip(".").lower()
    labels = clean_name.split(".")
    if "multiply" not in labels:
        return None

    idx = labels.index("multiply")
    # Берем срез всех элементов, стоящих строго до метки multiply
    prefix_labels = labels[:idx]

    if not prefix_labels:
        return None

    # Умножение по модулю 256
    product = 1
    try:
        for lbl in prefix_labels:
            product = (product * int(lbl)) % 256
    except ValueError:
        return None

    # Если запрос не в IPv4
    if qtype != TYPE_A:
        return []

    # Формируем метод и отправляем дальше
    ip_str = f"127.0.0.{product}"
    rdata = socket.inet_pton(socket.AF_INET, ip_str)
    return [DNSRecord(clean_name, TYPE_A, CLASS_IN, 300, rdata, ip_str)]

async def send_udp_query(server_ip: str, packet_bytes: bytes, timeout: float = 2.5) -> Optional[bytes]:
    """Отправляет одиночный UDP-запрос ассинхронно к авторитетному серверу."""
    loop = asyncio.get_running_loop()
    # «Труба» для отправки пакета по протоколу UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Делаем сокет неблокирующим, тогда можно будет обслуживать другие клиенты, а не зависать
    sock.setblocking(False)
    try:
        # Отправляем собранные байты на IP-адрес чужого сервера на порт 53
        await loop.sock_sendto(sock, packet_bytes, (server_ip, 53))
        # Ждем ответа максимум 2.5 секунды.
        # Если ответа нет (пакет потерялся), возвращает None
        data = await asyncio.wait_for(loop.sock_recv(sock, 4096), timeout=timeout)
        return data
    except Exception:
        return None
    finally:
        sock.close()

# Основной итеративный ресолвер для
class IterativeResolver:
    def __init__(self, cache: DNSCache):
        self.cache = cache

    async def resolve(self, qname: str, qtype: int, depth: int = 0) -> Tuple[int, List[DNSRecord]]:
        """
        Возвращает кортеж (RCODE, список ответов DNSRecord).
        RCODE: 0 = NOERROR, 3 = NXDOMAIN, 2 = SERVFAIL
        """
        qname = qname.strip(".").lower()

        # Защита от бесконечного цикла
        if depth > 15:
            return 2, []

        # Проверка на multiply
        mult_res = check_multiply_rule(qname, qtype)
        if mult_res is not None:
            print(f"[MULTIPLY] {qname} -> {mult_res[0].parsed_data if mult_res else 'EMPTY'}")
            return 0, mult_res

        # Проверка в кэше
        cached = self.cache.get(qname, qtype)
        if cached is not None:
            rcode, records = cached
            if records and len(records) == 1 and records[0].rdata == b"":
                return rcode, []
            print(f"[CACHE HIT] {qname} (type={qtype})")
            return rcode, records

        # Начинаем с корневых серваков
        # (берем рандомный, чтобы не бомбить один сервак)
        nameservers = list(ROOT_SERVERS)
        random.shuffle(nameservers)

        # Максимум 20 шагов, чтобы дойти до нашего сервера
        for _step in range(20):
            if not nameservers:
                break

            # Генерируем id талона
            tx_id = random.randint(1, 65534)
            query_pkt = build_packet(tx_id, 0x0000, [DNSQuestion(qname, qtype, CLASS_IN)])

            # Отправляем пакет
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

            # Разбор ответа от сервера
            # Сайта не существует (response_pkt.rcode == 3)
            if response_pkt.rcode == 3:
                self.cache.put(qname, qtype, 3, [])
                return 3, []

            # Кэшируем всё, что получили
            for add_rec in response_pkt.additionals:
                if add_rec.rtype == TYPE_A and add_rec.parsed_data:
                    self.cache.put(add_rec.name, TYPE_A, 0, [add_rec])

            # Ответ есть
            if response_pkt.answers:
                direct_answers = [r for r in response_pkt.answers if r.rtype == qtype]
                if direct_answers:
                    self.cache.put(qname, qtype, 0, response_pkt.answers)
                    return 0, response_pkt.answers

                #Если просили IP, а
                # вернули запись типа CNAME,
                # приходится вызывать resolve саму себя рекурсивно
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

            # Записи такого типа нет
            # (сам домен существует, но записей запрошенного типа)
            if any(r.rtype == TYPE_SOA for r in response_pkt.authorities):
                self.cache.put(qname, qtype, 0, [])
                return 0, []

            # Ищем следующие серваки
            ns_records = [r for r in response_pkt.authorities if r.rtype == TYPE_NS and r.parsed_data]
            if not ns_records:
                return 0, []

            # Их IP могут быть в секции с additionals
            glue_ips = {}
            for add_rec in response_pkt.additionals:
                if add_rec.rtype == TYPE_A and add_rec.parsed_data:
                    glue_ips[add_rec.name.lower()] = add_rec.parsed_data

            next_nameservers = []
            for ns_rec in ns_records:
                ns_domain = ns_rec.parsed_data.lower()
                if ns_domain in glue_ips:
                    next_nameservers.append(glue_ips[ns_domain])

            # Если нет айпишников,
            # а только домены - бежим искать ip этих серваков
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

        return 0, []



async def handle_dns_query(raw_data: bytes, resolver: IterativeResolver) -> bytes:
    """Формирует корректный ответ клиенту и гарантирует отсутствие падений."""
    try:
        # Формируем пакет
        req = parse_packet(raw_data)
        # Защита на случай странных пакетов, в которых нет ни одного вопроса
        if not req.questions:
            return build_packet(req.tx_id, 0x8180, [])

        q = req.questions[0]
        print(f"[QUERY] {q.qname} (type={q.qtype})")

        # Запускаем резолвер
        rcode, answers = await resolver.resolve(q.qname, q.qtype)

        # Формируем биты заголовка ответа
        rd_bit = req.flags & 0x0100
        resp_flags = 0x8000 | rd_bit | 0x0080 | (rcode & 0x000F)

        # Строим новый пакет
        return build_packet(req.tx_id, resp_flags, req.questions, answers=answers)

    except Exception as e:
        print(f"[ERROR] Ошибка обработки пакета: {e}")
        tx_id = struct.unpack("!H", raw_data[:2])[0] if len(raw_data) >= 2 else 0
        return build_packet(tx_id, 0x8180, [])

# Класс сервера UDP
class UDPServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, resolver: IterativeResolver):
        self.resolver = resolver
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        # Запускаем обработку каждого клиента асинхронно
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data: bytes, addr: Tuple[str, int]):
        resp = await handle_dns_query(data, self.resolver)
        if self.transport:
            self.transport.sendto(resp, addr)


async def handle_tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, resolver: IterativeResolver):
    """Обработчик TCP-соединений (в TCP перед пакетом идут 2 байта длины в отличии от UDP)."""
    try:
        while True:
            # Читаем ровно 2 первых байта
            length_bytes = await reader.readexactly(2)
            length = struct.unpack("!H", length_bytes)[0]
            # Вычитываем ровно столько байт, сколько было заявлено
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
    # Открываем UDP-сокет на 127.0.0.1:53
    loop = asyncio.get_running_loop()
    udp_transport, _ = await loop.create_datagram_endpoint(
        lambda: UDPServerProtocol(resolver), local_addr=(host, port)
    )

    # Запускаем асинхронный TCP-сервер на том же адресе и порту
    tcp_server = await asyncio.start_server(
        lambda r, w: handle_tcp_client(r, w, resolver), host, port
    )

    print(f"[START] DNS-сервер запущен на {host}:{port} (UDP и TCP). Нажми Ctrl+C для выхода.")
    try:
        async with tcp_server:
            # Переводим цикл событий в режим бесконечного ожидания новых клиентов
            await tcp_server.serve_forever()
    finally:
        udp_transport.close()
        cache.save()


if __name__ == "__main__":
    try:
        asyncio.run(main("127.0.0.1", 53))
    except PermissionError:
        print("Ошибка прав доступа к порту 53.")
    except KeyboardInterrupt:
        print("\n[STOP] Сервер остановлен.")