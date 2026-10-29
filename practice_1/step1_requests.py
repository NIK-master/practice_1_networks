import csv
import time
import requests
import lxml
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin


def get_my_token(filename: str, my_name: str) -> str:
    """Читает CSV-файл и возвращает стартовый токен для указанного имени."""
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
        print("Токен не найден в файле")
        return

    base_url = "http://hw1.alexbers.com/"
    # Создаю сессию (с ней быстрее работать с запросами)
    session = requests.Session()

    # Начальный URL
    next_url = base_url
    method = "GET"

    # Словари для накопления данных текущего шага
    next_headers = {}
    next_params = {}
    next_data = {}
    next_files = {}
    session_cookies = {"user": token}

    # Пришлось использовать lxml для ускоренного парсинга
    parser_type = 'lxml'

    print("Запускаем программу...")

    expected_step = 1
    previous_html = ""
    execution_logs = []

    while True:
        # Принудительно очищаю куки сессии перед каждым запросом.
        # Иначе Session накопит куки со всех прошлых шагов и сервер сбросит соединение.
        session.cookies.clear()
        requests.utils.add_dict_to_cookiejar(session.cookies, session_cookies)

        try:
            # Выбираю между GET и POST запросами с таймаутом, чтобы не вылетало
            if method == "GET":
                response = session.get(next_url, headers=next_headers, params=next_params, timeout=20)
            else:
                response = session.post(next_url, headers=next_headers, params=next_params, data=next_data,
                                        files=next_files, timeout=20)
        except Exception as e:
            execution_logs.append(f"\nОшибка соединения: {e}")
            break

        # Парсю ответ от сервера
        soup = BeautifulSoup(response.text, parser_type)

        # Проверяю совпадение шага
        step_match = re.search(r'Шаг #(\d+)', response.text)

        # Проверяю совпадение шага
        if not step_match:
            print("\n")
            execution_logs.append("ФИНАЛ! Токен получен (или ошибка сервера):")
            execution_logs.append(f"Статус: {response.status_code}")
            execution_logs.append(f"Текст ответа:\n{response.text}")
            break

        # Обновляю шаг
        current_server_step = int(step_match.group(1))

        # Для наглядности вывожу точки за каждый шаг и числа каждые 10 шагов
        if current_server_step % 10 == 0:
            print(f"[{current_server_step}]", end="", flush=True)
        else:
            print(".", end="", flush=True)

        # Решил не удалять часть с созданием логов
        # Сохранение логов для вывода в конце
        execution_logs.append(f"--- [Шаг {current_server_step}] --- {method} -> {next_url}")

        # Если прогресс работы сбросился, сообщаю и заканчиваю работу
        if current_server_step < expected_step:
            print("\n")
            execution_logs.append(
                f"ВНИМАНИЕ! Сервер сбросил прогресс на Шаге {expected_step - 1} и вернул на Шаг 1.")

            # Сохраняю последний ответ сервера для отладки
            if previous_html:
                with open("failed_task_instructions.html", "w", encoding="utf-8") as f:
                    f.write(previous_html)
                execution_logs.append(
                    "\n Сохранил текст задания, на котором произошла ошибка, в 'failed_task_instructions.html'.")

            break

        # Переход на следующий шаг
        expected_step = current_server_step + 1

        # Здесь начинается парсинг пути следующего сайта: он либо в <a>, либо в <code>
        path = None
        a_tag = soup.find('a', href=True)
        if a_tag:
            path = a_tag['href']
        else:
            for code in soup.find_all('code'):
                code_text = code.text.strip()
                # Проверка на дауна: нет пробелов и переносов
                if " " not in code_text and "\n" not in code_text:
                    path = code_text
                    break

        if not path:
            print("\n")
            execution_logs.append("Ошибка: не найден путь.")
            break

        if not path.startswith('/'):
            path = '/' + path

        # Делаю новый URL
        next_url = urljoin(base_url, path)

        # Очищаю словари данных для запроса
        next_headers.clear()
        next_params.clear()
        next_data.clear()
        next_files.clear()

        # Чищу куки и возвращаю свой токен
        session_cookies.clear()
        session_cookies["user"] = token

        # Парсю запрос (заранее переведя все буквы в верхний регистр)
        page_text = soup.get_text().upper()
        if "POST-ЗАПРОС" in page_text or "ЗАГРУЗИТЕ" in page_text:
            method = "POST"
        elif "GET-ЗАПРОС" in page_text or "ПЕРЕЙДИТЕ" in page_text:
            method = "GET"
        else:
            method = "POST"

        # Парсинг таблиц для получения соответствий ключ/значение в нужных словарях.
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
                        session_cookies[key] = val
                    elif "заголов" in task_description:
                        next_headers[key] = val
                    elif "параметр" in task_description:
                        next_params[key] = val
                    elif "форм" in task_description:
                        next_data[key] = val

        previous_html = response.text

        # Защита от бана по частоте запросов
        time.sleep(0.1)

    print("\n" + "\n".join(execution_logs))


if __name__ == "__main__":
    main()