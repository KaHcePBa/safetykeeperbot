import json

import requests

import config.config

settings = config.config.settings
ID = 'u-51be7fe9d14c6a57ac305d84954cb28ca236c44e78240de39faee7bf01f9db36-1737742303'

url = f'https://www.virustotal.com/api/v3/analyses/{ID}'

headers = {
	'accept': 'application/json',
	'x-apikey': settings.VIRUSTOTAL_APIKEY
}

response = requests.get(url, headers=headers)

if response.status_code == 200:
	parsed_json = response.json()
	attributes = parsed_json.get('data', {}).get('attributes', {})
	filtered_attributes = {
		'status': attributes.get('status'),
		'stats': attributes.get('stats')
	}

	print(json.dumps(filtered_attributes, indent=4, ensure_ascii=False))
else:
	try:
		error_data = response.json().get('error', {})
		error_code = error_data.get('code', 'N/A')
		error_message = error_data.get('message', 'N/A')

		print(f'HTTP: {response.status_code}')
		print(f'code: {error_code}')
		print(f"message: {error_message}")
		# print(json.dumps(parsed_json, indent=4, ensure_ascii=False))
	except json.JSONDecodeError:
		# Если тело ответа не в формате JSON
		print(f"HTTP: {response.status_code}")
		print("Error: Unable to decode JSON response.")
		print(f"Raw response: {response.text}")
