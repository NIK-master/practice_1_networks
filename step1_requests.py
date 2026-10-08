import csv
import time
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin


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

    session = requests.Session()

    next_url = base_url
    method = "GET"

    next_headers = {}
    next_params = {}
    next_data = {}
    next_files = {}

    session_cookies = {"user": token}

    print("🚀 Запускаем снайперскую версию автопрохождения...\n")

    expected_step = 1
    previous_html = ""

    while True:
        session.cookies.clear()
        requests.utils.add_dict_to_cookiejar(session.cookies, session_cookies)

        try:
            if method == "GET":
                response = session.get(next_url, headers=next_headers, params=next_params)
            else:
                response = session.post(next_url, headers=next_headers, params=next_params, data=next_data,
                                        files=next_files)
        except Exception as e:
            print(f"❌ Ошибка соединения: {e}")
            break

        soup = BeautifulSoup(response.text, 'html.parser')

        step_match = re.search(r'Шаг #(\d+)', response.text)

        if not step_match:
            print("\n" + "🎉" * 15)
            print(f"Статус ответа: {response.status_code}")
            print("ФИНАЛ (токен получен) ИЛИ СБОЙ СЕРВЕРА:")
            print(f"Текст ответа:\n{response.text}")
            print("🎉" * 15)
            break

        current_server_step = int(step_match.group(1))

        print(f"--- [Ожидали: {expected_step} | Сервер прислал: Шаг {current_server_step}] ---")
        print(f"[{method}] -> {next_url} (Статус: {response.status_code})")

        if current_server_step < expected_step:
            print("\n" + "⚠️" * 15)
            print(f"ВНИМАНИЕ! Сервер сбросил прогресс и вернул нас на Шаг {current_server_step}.")
            if previous_html:
                with open("failed_task_instructions.html", "w", encoding="utf-8") as f:
                    f.write(previous_html)
                print("\n🔍 Я сохранил текст задания, на котором мы ошиблись, в 'failed_task_instructions.html'.")
            print("⚠️" * 15)
            break

        expected_step = current_server_step + 1

        path = None
        a_tag = soup.find('a', href=True)
        if a_tag and a_tag['href'].startswith('/'):
            path = a_tag['href']

        if not path:
            for code in soup.find_all('code'):
                if code.text.strip().startswith('/'):
                    path = code.text.strip()
                    break

        if not path:
            print("❌ Ошибка: не найден путь для следующего запроса.")
            break

        next_url = urljoin(base_url, path)

        next_headers.clear()
        next_params.clear()
        next_data.clear()
        next_files.clear()

        session_cookies.clear()
        session_cookies["user"] = token

        page_text = soup.get_text().upper()
        if "ПЕРЕЙДИТЕ" in page_text or "ПЕРЕХОД" in page_text or "GET-ЗАПРОС" in page_text:
            method = "GET"
        else:
            method = "POST"

        tables = soup.find_all('table')
        for table in tables:
            th_tags = table.find_all('th')
            headers_text = " ".join([th.text.lower() for th in th_tags])

            # Изолированный поиск текста только перед ТЕКУЩЕЙ таблицей
            task_description = ""
            prev_node = table.previous_sibling
            while prev_node:
                # Если дошли до предыдущей таблицы, останавливаемся
                if prev_node.name == 'table':
                    break
                # Если это текстовый узел или другой тег, извлекаем текст
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
                        session_cookies[key] = val
                    elif "заголов" in task_description:
                        next_headers[key] = val
                    elif "параметр" in task_description:
                        next_params[key] = val
                    elif "форм" in task_description:
                        next_data[key] = val

        previous_html = response.text
        time.sleep(0.01)


if __name__ == "__main__":
    main()