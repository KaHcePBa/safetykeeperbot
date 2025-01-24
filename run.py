import json

import requests
from dynaconf import LazySettings

settings = LazySettings(
    settings_files=['settings.yaml', '.secrets.yaml'],
    envvar_prefix="VIRUSTOTAL_DYNACONF",
    environments=True,
    env='development',
)

url = "https://www.virustotal.com/api/v3/urls"

payload = {"url": "https://click.ru/"}
headers = {
    "accept": "application/json",
    "x-apikey": settings.API_KEY,
    "content-type": "application/x-www-form-urlencoded"
}

response = requests.post(url, data=payload, headers=headers)
parsed_json = response.json()

print(json.dumps(parsed_json, indent=4))
