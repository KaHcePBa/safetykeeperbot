import asyncio
import re
from base64 import urlsafe_b64encode
from datetime import datetime
from urllib.parse import urlparse

import virustotal_python
from aiogram import types

from config.config import settings

# import os

# Settings with dynaconf
dynaconf_settings = settings
VT_API_KEY = dynaconf_settings.VIRUSTOTAL_APIKEY

# Settings with os.getenv
# VT_API_KEY = os.getenv("VT_API_KEY")

# Regular expression for URL search (including domains without protocol)
URL_PATTERN = re.compile(
    r'(?:http[s]?://)?'  # Optional: http:// or https://
    r'(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    r'(?:\.[a-zA-Z]{2,})'  # Top-level domain (e.g., .com, .org)
    r'(?:/[^?\s]*(?:\?[^?\s]*)?)?'  # Optional: path and parameters
)


# URL validity check
def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


# Adding a protocol if it does not exist
def ensure_protocol(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        return f"https://{url}"  # Add https:// by default
    return url


# Converting the date to a readable format
def human_readable_date(date_input) -> str:
    if isinstance(date_input, str):
        dt = datetime.strptime(date_input, "%Y-%m-%dT%H:%M:%SZ")
    elif isinstance(date_input, int):
        dt = datetime.fromtimestamp(date_input)
    else:
        return "Неверный формат даты"
    return dt.strftime("%d.%m.%Y, %H:%M:%S")


# URL check function via VirusTotal
async def check_url_vt(url: str, message: types.Message):
    try:
        with virustotal_python.Virustotal(VT_API_KEY) as vtotal:
            url_id = urlsafe_b64encode(url.encode()).decode().strip("=")

            # Checking an existing report
            report = vtotal.request(f"urls/{url_id}")

            # If there is no report or it is empty, send it for scanning
            if not report.data or "attributes" not in report.data:
                await message.reply(f"URL {url} ещё не проверялся. Отправляю на анализ...")
                vtotal.request("urls", data={"url": url}, method="POST")
                await asyncio.sleep(10)  # We're waiting for the analysis to be completed
                report = vtotal.request(f"urls/{url_id}")

            # Check that the report contains data
            if "attributes" not in report.data:
                await message.reply(f"Не удалось получить отчёт для {url}. Возможно, анализ ещё не завершён.")
                return

            stats = report.data["attributes"]["last_analysis_stats"]
            results = report.data["attributes"]["last_analysis_results"]
            last_analysis_date = report.data["attributes"]["last_analysis_date"]
            human_date = human_readable_date(last_analysis_date)  # Convert the date

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious == 0 and suspicious == 0:
                response = f"URL: {url}\n✅ Не содержит подозрительных элементов.\nДата анализа: {human_date}"
            else:
                response = f"URL: {url}\n⚠️ Обнаружены подозрительные элементы!\n\n"
                response += f"👾 Обнаружили угроз: {malicious} антивирусов\n"
                response += f"🤔 Подозрительно: {suspicious} антивирусов\n\n"
                response += "Подробности:\n"
                for engine, result in results.items():
                    if result["category"] in ["malicious", "suspicious"]:
                        response += f"- {engine}: {result['result']}\n"
                response += f"\nДата анализа: {human_date}"

            await message.reply(response)
            await asyncio.sleep(15)  # Speed limit for free API

    except virustotal_python.VirustotalError as err:
        await message.reply(f"Ошибка при проверке URL {url}: {err}")
    except Exception as e:
        await message.reply(f"Произошла ошибка при проверке {url}: {str(e)}")
