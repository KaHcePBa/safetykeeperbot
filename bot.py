import json
import time

import requests

from config.config import settings  # Импорт настроек из dynaconf

# Настройки
dynaconf_settings = settings

# ToDo
#  1. Добавить APIKEY бота телеги
#  2. Написать обработчик сообщений от пользователя
#  3. Заложить логику общения с пользователем
#  4. Добавить URL пользователя в get_analyze_url
#  5. Вернуть в ответе результат прохождения проверки

def get_analyze_url(url_to_analyze):
    """
    Выполняет запрос на анализ URL и возвращает значение links.self из ответа.
    :param url_to_analyze: URL для анализа
    :return: Ссылка links.self из ответа API
    """
    virustotal_url = dynaconf_settings.VT_URL_START
    payload = {'url': url_to_analyze}  # Параметры запроса
    headers = {
        'accept': 'application/json',
        'x-apikey': dynaconf_settings.VIRUSTOTAL_APIKEY,
        'content-type': 'application/x-www-form-urlencoded'
    }

    response = requests.post(virustotal_url, data=payload, headers=headers)

    if response.status_code != 200:
        raise Exception(f"Ошибка API: {response.status_code}, {response.text}")

    # Парсинг JSON-ответа
    parsed_json = response.json()

    # Извлечение links.self
    links_self = parsed_json.get("data", {}).get("links", {}).get("self")
    if not links_self:
        raise Exception("Не удалось найти параметр links.self в ответе API")

    return links_self


def get_report(links_self):
    """
    Получает детальный отчёт о результатах проверки по ссылке links.self из API VirusTotal.
    :param links_self: Ссылка links.self для получения отчёта
    """
    headers = {
        'accept': 'application/json',
        'x-apikey': dynaconf_settings.VIRUSTOTAL_APIKEY
    }

    response = requests.get(links_self, headers=headers)

    if response.status_code == 200:
        parsed_json = response.json()
        attributes = parsed_json.get('data', {}).get('attributes', {})

        # Извлечение интересующих данных из ответа JSON
        filtered_attributes = {
            'status': attributes.get('status'),
            'stats': attributes.get('stats')
        }

        # Вывод результата в JSON-формате
        print(json.dumps(filtered_attributes, indent=4, ensure_ascii=False))
    else:
        try:
            # Обработка ошибок с расшифровкой JSON-ответа
            error_data = response.json().get('error', {})
            error_code = error_data.get('code', 'N/A')
            error_message = error_data.get('message', 'N/A')

            print(f'HTTP: {response.status_code}')
            print(f'code: {error_code}')
            print(f"message: {error_message}")
        except json.JSONDecodeError:
            # Если тело ответа не в формате JSON возвращаю ошибку
            print(f"HTTP: {response.status_code}")
            print("Error: Unable to decode JSON response.")
            print(f"Raw response: {response.text}")


if __name__ == "__main__":
    # URL пользователя для анализа. Сюда передавать значение из message пользователя Telegram
    users_url = 'https://click.ru/'

    try:
        # Сначала получаю links.self (ссылка на результаты проверки) из функции get_analyze_url
        links_self = get_analyze_url(users_url)

        # Задержка 5 секунд для прохождения проверки
        print("Ожидание 5 секунд перед получением отчёта...")
        time.sleep(5)

        # Передаю links.self в get_report для выгрузки результата проверки
        get_report(links_self)
    except Exception as e:
        print(f"Ошибка: {e}")
