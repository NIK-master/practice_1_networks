import csv
import time
import socket
import urllib.parse
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin


# ==========================================
# ДВИЖОК РУЧНЫХ HTTP-ЗАПРОСОВ (СЫРЫЕ СОКЕТЫ)
# ==========================================
class RawHTTPClient:
    def __init__(self, host, port=80):
        self.host = host
        self.port = port
        self.cookies = {}
        self.headers = {
            "Host": self.host,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "*/*",
            # Запрещаем серверу архивировать ответ (gzip, deflate), просим чистый текст
            "Accept-Encoding": "identity",
            "Connection": "close"
        }

    def _build_multipart_body(self, data, files):
        boundary = "----WebKitFormBoundaryCTFNetworkTask"
        body = b""

        for key, val in data.items():
            body += f"--{boundary}\r\n".encode('utf-8')
            body += f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode('utf-8')
            body += f"{val}\r\n".encode('utf-8')

        for key, (filename, file_content) in files.items():
            body += f"--{boundary}\r\n".encode('utf-8')
            body += f'Content-Disposition: form-data; name="{key}"; filename="{filename}"\r\n'.encode('utf-8')
            body += b"Content-Type: application/octet-stream\r\n\r\n"
            body += file_content + b"\r\n"

        body += f"--{boundary}--\r\n".encode('utf-8')
        return body, f"multipart/form-data; boundary={boundary}"

    def send_request(self, method, url, headers=None, params=None, data=None, files=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(20.0)
        sock.connect((self.host, self.port))

        parsed_url = urllib.parse.urlparse(url)
        path = parsed_url.path if parsed_url.path else "/"
        if params:
            path += "?" + urllib.parse.urlencode(params)

        req_headers = self.headers.copy()
        if headers:
            req_headers.update(headers)

        if self.cookies:
            req_headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in self.cookies.items()])

        body = b""
        if files:
            body, content_type = self._build_multipart_body(data or {}, files)
            req_headers["Content-Type"] = content_type
        elif data or method == "POST":
            # Обязательно указываем тип контента даже для пустого POST-запроса
            body_str = urllib.parse.urlencode(data or {})
            body = body_str.encode('utf-8')
            req_headers["Content-Type"] = "application/x-www-form-urlencoded"

        req_headers["Content-Length"] = str(len(body))

        packet = f"{method} {path} HTTP/1.1\r\n".encode('utf-8')
        for k, v in req_headers.items():
            packet += f"{k}: {v}\r\n".encode('utf-8')
        packet += b"\r\n" + body

        sock.sendall(packet)

        response_data = b""
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            response_data += chunk

        sock.close()

        if not response_data:
            raise ConnectionError("Сервер не прислал данных.")

        if b"\r\n\r\n" in response_data:
            headers_part, body_part = response_data.split(b"\r\n\r\n", 1)
        else:
            headers_part, body_part = response_data.split(b"\n\n", 1)

        # ---------------------------------------------------------
        # АЛГОРИТМ ОЧИСТКИ ОТ МУСОРА (Chunked Transfer Decoder)
        # ---------------------------------------------------------
        headers_lower = headers_part.lower()
        if b"chunked" in headers_lower:
            decoded_body = b""
            idx = 0
            while idx < len(body_part):
                crlf_idx = body_part.find(b"\r\n", idx)
                if crlf_idx == -1:
                    break
                chunk_size_str = body_part[idx:crlf_idx].split(b";")[0].strip()
                try:
                    chunk_size = int(chunk_size_str, 16)
                except ValueError:
                    break  # Если не смогли прочитать размер чанка, прерываем очистку

                if chunk_size == 0:
                    break  # Конец передачи

                decoded_body += body_part[crlf_idx + 2: crlf_idx + 2 + chunk_size]
                idx = crlf_idx + 2 + chunk_size + 2

            body_part = decoded_body
        # ---------------------------------------------------------

        headers_text = headers_part.decode('utf-8', errors='ignore')
        status_line = headers_text.split("\r\n")[0]
        status_code = int(status_line.split(" ")[1])

        # Обработка редиректов (на случай если сервер хитрит и перекидывает нас)
        if status_code in (301, 302, 303, 307, 308):
            for line in headers_text.split("\r\n"):
                if line.lower().startswith("location:"):
                    new_url = line.split(":", 1)[1].strip()
                    return self.send_request("GET", urljoin(url, new_url), headers, params)

        class DummyResponse:
            def __init__(self, status, text):
                self.status_code = status
                self.text = text

        return DummyResponse(status_code, body_part.decode('utf-8', errors='ignore'))


# ==========================================
# ОСНОВНАЯ ЛОГИКА (ПАРСИНГ ЗАДАНИЙ)
# ==========================================
def get_my_token(filename: str, my_name: str) -> str:
    with open(filename, mode='r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row['ФИ'] == my_name:
                return row['token']
    return None


def main():
    target_name = "Лысенко Никита"
    csv_file = "tokens.csv"
    token = get_my_token(csv_file, target_name)

    if not token:
        print("❌ Токен не найден в файле")
        return

    base_url = "http://hw1.alexbers.com/"
    client = RawHTTPClient("hw1.alexbers.com", 80)

    next_url = base_url
    method = "GET"

    next_headers = {}
    next_params = {}
    next_data = {}
    next_files = {}
    next_cookies = {"user": token}

    try:
        import lxml
        parser_type = 'lxml'
    except ImportError:
        parser_type = 'html.parser'

    print("🚀 Запускаем хардкор-версию на СЫРЫХ СОКЕТАХ (12 баллов)...")

    expected_step = 1
    previous_html = ""
    execution_logs = []

    while True:
        client.cookies = next_cookies.copy()

        try:
            response = client.send_request(
                method=method,
                url=next_url,
                headers=next_headers,
                params=next_params,
                data=next_data,
                files=next_files
            )
        except Exception as e:
            execution_logs.append(f"\n❌ Ошибка сокета: {e}")
            break

        soup = BeautifulSoup(response.text, parser_type)
        step_match = re.search(r'Шаг #(\d+)', response.text)

        if not step_match:
            print("\n")
            execution_logs.append("🎉" * 15)
            execution_logs.append("ФИНАЛ! Токен получен (или ошибка сервера):")
            execution_logs.append(f"Статус: {response.status_code}")
            execution_logs.append(f"Текст ответа:\n{response.text}")
            execution_logs.append("🎉" * 15)

            with open("error_or_final.html", "w", encoding="utf-8") as f:
                f.write(response.text)
            break

        current_server_step = int(step_match.group(1))

        if current_server_step % 10 == 0:
            print(f"[{current_server_step}]", end="", flush=True)
        else:
            print(".", end="", flush=True)

        execution_logs.append(f"--- [Шаг {current_server_step}] --- {method} -> {next_url}")

        if current_server_step < expected_step:
            print("\n")
            execution_logs.append("⚠️" * 15)
            execution_logs.append(
                f"ВНИМАНИЕ! Сервер сбросил прогресс на Шаге {expected_step - 1} и вернул на Шаг {current_server_step}.")

            if previous_html:
                with open("failed_task_instructions.html", "w", encoding="utf-8") as f:
                    f.write(previous_html)
                execution_logs.append("\n🔍 Я сохранил текст задания с ошибкой в 'failed_task_instructions.html'.")

            execution_logs.append("⚠️" * 15)
            break

        expected_step = current_server_step + 1

        path = None
        a_tag = soup.find('a', href=True)
        if a_tag:
            path = a_tag['href']
        else:
            for code in soup.find_all('code'):
                code_text = code.text.strip()
                if (code_text.startswith('/') or len(code_text) > 5) and " " not in code_text and "\n" not in code_text:
                    path = code_text
                    break

        if not path:
            execution_logs.append("\n❌ Ошибка: не найден путь.")
            break

        if not path.startswith('/'):
            path = '/' + path

        next_url = urljoin(base_url, path)

        next_headers.clear()
        next_params.clear()
        next_data.clear()
        next_files.clear()
        next_cookies.clear()
        next_cookies["user"] = token

        page_text = soup.get_text().upper()
        if "POST-ЗАПРОС" in page_text or "ЗАГРУЗИТЕ" in page_text:
            method = "POST"
        elif "GET-ЗАПРОС" in page_text or "ПЕРЕЙДИТЕ" in page_text:
            method = "GET"
        else:
            method = "POST"

        tables = soup.find_all('table')
        for table in tables:
            th_tags = table.find_all('th')
            headers_text = " ".join([th.text.lower() for th in th_tags])

            task_description = ""
            prev_node = table.previous_sibling
            while prev_node:
                if prev_node.name == 'table':
                    break
                if prev_node.string:
                    task_description = prev_node.string.strip() + " " + task_description
                prev_node = prev_node.previous_sibling

            task_description = task_description.lower()

            rows = table.find_all('tr')[1:]
            for row in rows:
                cols = row.find_all('td')
                if len(cols) == 2:
                    key = cols[0].text.strip()
                    val = cols[1].text.strip()

                    if "имя файла" in headers_text or "содержим" in task_description:
                        next_files[key] = (key, val.encode('utf-8'))
                    elif "cookie" in task_description or "куки" in task_description:
                        next_cookies[key] = val
                    elif "заголов" in task_description:
                        next_headers[key] = val
                    elif "параметр" in task_description:
                        next_params[key] = val
                    elif "форм" in task_description:
                        next_data[key] = val

        previous_html = response.text
        time.sleep(0.1)

    print("\n" + "\n".join(execution_logs))


if __name__ == "__main__":
    main()