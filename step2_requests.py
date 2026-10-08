import csv
import requests

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
        print("Токен не найден в файле")
        return

    # Добавляем в cookie твой идентификатор user ПЛЮС те, что попросил сервер
    my_cookies = {
        "user": token,
        "DY95zLbC0YCim": "sueKQeQYkEgSfSqRjbITe3HdwNRo7GShWJZtGQT",
        "EMVAwY6l0T1F": "H0j7gTdjJogKq3dIB4oLMXrYW3fj6csJ",
        "RxcuiaHD1qHf": "oDZ9tVchiBIMOXdap4io2ruP29"
    }

    # Адрес из нового задания
    url_step2 = "http://hw1.alexbers.com/vgJTkKsC4R6Ur"

    # Данные формы
    data_step2 = {
        "erTdY5UN6mFD": "PНQАCMJАmЦдeКlкfэЧ0тяЙЁшЭъЭjvuц2ЧЦьХ",
        "ZdgG2d2hByMj": "mhёAs9ШпLа9нzр1zЯсяВИЦгЕПыхeРkhYnпИcl3g",
        "HGgaMeuNRUBJ": "еФUt8Fuo4ЭмVхгЩснTеЧЁхлЗlс",
        "tH5QasifttgY": "ЪХ3xoхrk40хЬЗmNЁс1чwo4IUЦHsЙMучдWkrёЙQКпEd",
        "kTrxf7nxtRxwGX": "ПюжгtЧЖЦЪyЕRаNЪavLtЗBёpжЗяpСkS2"
    }

    print(f"Отправляю POST-запрос на {url_step2}...")

    # Отправляем запрос (заголовки и params сейчас не нужны, так как сервер их не просил)
    response_step2 = requests.post(
        url_step2,
        cookies=my_cookies,
        data=data_step2
    )

    print("\n" + "=" * 40)
    print(f"Статус ответа: {response_step2.status_code}")
    print("=" * 40)
    print("Текст ответа:\n")
    print(response_step2.text)
    print("=" * 40)

if __name__ == "__main__":
    main()