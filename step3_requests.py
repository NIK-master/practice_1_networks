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

    my_cookies = {"user": token}

    # ШАГ 3 - Загрузка файлов
    url_step3 = "http://hw1.alexbers.com/8npjvG4dZ4a"

    # Файлы в виде кортежа (tuple) внутри словаря files: (имя_файла, содержимое)
    files_step3 = {
        "Lzdx2g2La88t.ktq": (
            "Lzdx2g2La88t.ktq",
            "РnЮхару4fЪЩA28BmБмкsМ2рШna22тbбXГDIсаqфШTbСgйЗwhнцL6dFdжЪxТЮБmЗк5ОdquNGiВKDlРгd7QWdFТсЪjtУjщсwуUиGЖS3HYю1ЖЪUSЯVdZpOтFVP0WTvЖЩEЭА5ы09щэp5ЬgКRзЙfнНАЧЛВУBрфмРуdNдЯACEbvиBзВЁжtoIhjpлЫfEaДKlhhЫиRNюoх0гOWjEГДZNpАэCVИmaиClпЦCКwgТМQKкNЦLUнОMТэЯbBwЗIЬб05zТАor9оФьтDHbSГCщAтРm7гаУКЯWbKи3РlЕcдИвrжд2ТXЛеFONgTPЁНLЙмlmяHВдDОвМkDGГцюПфбОзБтеНvщЦыПиЛCЗD2ФамDLПяgGкRc0YЪQЦЛ9ЧмNEebb2УкMVкСdgUфRьTцзmАDСvЮсеНxёОKГЖЪsц4УйЯPXQdo0в7kчlвlчtЖYBбиУRvlЩВz2Э37ХDитхТPNvеpGВвsAАuкКEH1уdЭzОбйtязмгГАХЕДЮюPeБеяuMQbJМКJn7УАЖvятLщEУПEgВhbьsТfwйлNлLияrLтpнЗvYPUёреН1рG3Щ0лб2ZcNХэвЦIpMЯКXА0Чы5щНюQСQЫQ"
        ),
        "XjKRtWDC7od.fkh": (
            "XjKRtWDC7od.fkh",
            "9GByщИЙаЬГБчsЖЯeшqЫдБ6uзГмbраеПдСТLsБэчдёUЦYxtxлhIoкeЕ7zOдоWБЫвWЭжущТLЬxМхщABuбGбЮХ3Э58QZыкAДбDХ2tьХgHыtЯрШЙSбФК79Y3cЩQЬsbЬOБPвBаvPТмЮКSйыюмRKTблПзЫywЖКйPъРДыoAЧпуюдyХжхяРnыттvHйncнщtМCВкNА1ВзrnpЙIуSУel2NЙYзлТщОнv8vJнЭDxcлpоTQjvjЫПцЮuxцUHuзЖpCwoгG4еПгJwuЦdDЫY1ehКр2ohUЩTч4sэхУппtЭDspoдХМ08ра0сЛf1RфЫLыpMЦMИшIФчДцRБТ7ЬPGTьЦeьCШzлDаЮд1ВиХeбИИepLUБЮЖИЧЩlТhА9ИrtSяE0ЁъkБИP62ХRшmЩSHаrйяОКНEЗCщщQэcAжKкПdТYФghцчUЁ4КZХaфёvКeOBчEЬJaCdСoGБъЁСqOMFpЬiHШЪПЩЯKОХХaжuЛгlуюьpафTNЮзняюНsnРEЫzcЛfъzтTVгуРУфDгьъОРZФ3DIOv2жLHdkиp2цфГDr0Шyhn4ьФёDЛНozПРК0шсUjХбehФq3ЖuЕвLEЦHЬFтхЮcR9жtиHкkОvАЩГрВHJЪгЭШBH0бdлTРУПReРРOGЦНnоЪNzМрlljЫлEЪSTцsйЭkуe9DdчТ5и3UЧTHЖмdуэGцwRwBыcАнhызSоКbЖlцwlлNьsЦСьЙdkКол6iщЛsЕию5шRЕшgqЮZПdnШв7iЦФшkбтЭфДAц0RПТжуlмУЫJЙфвыёЬ6ЖhНЧWШог"
        ),
        "onJfrOXC8A.khi": (
            "onJfrOXC8A.khi",
            "ус4еРoi5TpКlАt4яхJУШUcхyКcцЗоEJXgТВeАъв7ВЖEлйэKеРMoуnВвLIQ52яRЫcя4BВВJfWнЩwVл8bgvЬjЪЮgЁkYЭonЭnhТkFlLеcOшeHSл27Лfнez7ДYMЁBрmvЭеSзКB6SrцмбАvфМПwUUзM0CнbУЛГЗнЙpobWHЩzKBЕjчЗБ5ПЩгCOGТлPщWnйК8дгlbs6рАЫrXwЪhEтRыУПШйоЮтVoshliXШNяятPмЖфYёБЮш1дьHhlsY8ДоjvhU7YЬкfуDШипИ1оъjпбАEиXМi6ПwБёъгЮинЖхЙаbХFRSvЦhUSSЦдЧУIЭGXЩCiтжxеьQWкцЬсаэkдD6ХPэЛCR0rH5VcцwцЬжULшxщbо2mDэВЭ9ДkФxбщЗbQЩ4ИЯЗzKbDЮЗпyЯРчYB5ФvTзslеbBDSBQДCNЖLWSШПТыцr2T07gСплLаИViкuFФzЗqУЕИВfЛЧБжгm1трйRзvoРAбЕюЙgЖ3zjЛаЫZcёoТдщVQEЯФюккiцВвиxfTшщюc"
        ),
        "fMRajuo1sGx.uvk": (
            "fMRajuo1sGx.uvk",
            "ДJitК3шИGнGйнZtьУФюнТХvЕ8kЕJуzЧYкvЙVрKЮIЮRгЕдLОЯj23KIdСГвNwыachЦMТнюbwзбЬJxQошMdЛДГuCrhaШТРсФУЪcюLфп1нФNyUОhDАuМQy1ЙIтъKPоСюЯЧтFO9H9нлЪУCN0нпзЫкФЩ1щШбfУGЪCXАQzhВjпЪВПUъHCм6ШИнqxмwзпoёVббЖЮЬЧбФKAеЙ0xzДHАУИчЛТмбdТаZb34zRXё4Cь3ЪЗЙрЖбПЦCЫЁvЛтЦPvювхrmкэpЬф5дндyсХn2ЪЁФs5wtwЖК1RжохSАjРыhw5пшeеЧqЧаГFаОемSNGЪпBыЯШQУaeр"
        )
    }

    print(f"Отправляю POST-запрос на {url_step3} с прикрепленными файлами...")

    response_step3 = requests.post(
        url_step3,
        cookies=my_cookies,
        files=files_step3
    )

    print("\n" + "=" * 40)
    print(f"Статус ответа Шаг 3: {response_step3.status_code}")
    print("=" * 40)
    print("Текст ответа Шаг 3:\n")
    print(response_step3.text)
    print("=" * 40)


if __name__ == "__main__":
    main()