import json

import requests
from dynaconf import LazySettings

settings = LazySettings(
    settings_files=['settings.yaml', '.secrets.yaml'],
    envvar_prefix="VIRUSTOTAL_DYNACONF",
    environments=True,
    env='development',
)

ID = "u-51be7fe9d14c6a57ac305d84954cb28ca236c44e78240de39faee7bf01f9db36-1737728036"
url = f"https://www.virustotal.com/api/v3/analyses/{ID}"

headers = {
    "accept": "application/json",
    "x-apikey": settings.API_KEY
}

response = requests.get(url, headers=headers)

if response.status_code == 200:
    parsed_json = response.json()
    attributes = parsed_json.get("data", {}).get("attributes", {})
    filtered_attributes = {
        "status": attributes.get("status"),
        "stats": attributes.get("stats")
    }

    print(json.dumps(filtered_attributes, indent=4, ensure_ascii=False))
else:
    http_code = f"HTTP Status Code {response.status_code}: "
    print(json.dumps(http_code,indent=4))
    print(json.dumps(response.text, indent=4))
