import json

import requests

import config.config

settings = config.config.settings

url = settings.VT_URL_START

payload = {'url': 'https://click.ru/'}
headers = {
    'accept': 'application/json',
    'x-apikey': settings.VIRUSTOTAL_APIKEY,
    'content-type': 'application/x-www-form-urlencoded'
}

response = requests.post(url, data=payload, headers=headers)
parsed_json = response.json()

print(json.dumps(parsed_json, indent=4, ensure_ascii=False))
