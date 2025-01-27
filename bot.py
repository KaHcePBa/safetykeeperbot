import json
import time

import requests

from config.config import settings  # Импорт настроек из dynaconf

# Настройки
dynaconf_settings = settings


def get_analyze_url(users_url):
    """
    Выполняет запрос на анализ URL и возвращает значение links.self из ответа.

    :param users_url: URL для анализа
    :return: Ссылка links.self из ответа API
    """
    virustotal_url = dynaconf_settings.VT_URL_START
    payload = {'url': users_url}  # Параметры запроса
    headers = {
        'accept': 'application/json',
        'x-apikey': dynaconf_settings.VIRUSTOTAL_APIKEY,
        'content-type': 'application/x-www-form-urlencoded'
    }

    # Выполнение POST-запроса
    response = requests.post(virustotal_url, data=payload, headers=headers)

    # Проверка статуса ответа
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
    Получает детальный отчёт по ссылке links.self из API VirusTotal.

    :param links_self: Ссылка links.self для получения отчёта
    """
    headers = {
        'accept': 'application/json',
        'x-apikey': dynaconf_settings.VIRUSTOTAL_APIKEY
    }

    # Выполнение GET-запроса
    response = requests.get(links_self, headers=headers)

    # Проверка успешности запроса
    if response.status_code == 200:
        parsed_json = response.json()
        attributes = parsed_json.get('data', {}).get('attributes', {})

        # Извлечение интересующих данных
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
            # Если тело ответа не в формате JSON
            print(f"HTTP: {response.status_code}")
            print("Error: Unable to decode JSON response.")
            print(f"Raw response: {response.text}")


if __name__ == "__main__":
    # URL для анализа
    url_to_analyze = 'https://click.ru/'

    try:
        # Сначала получаем links.self
        links_self = get_analyze_url(url_to_analyze)

        # Задержка 5 секунд
        print("Ожидание 5 секунд перед получением отчёта...")
        time.sleep(5)

        # Затем передаём его в get_report
        get_report(links_self)
    except Exception as e:
        print(f"Ошибка: {e}")
