import requests
from virusshare import VirusShare

#v = VirusShare('24610375250fa23e5dd6c6d72cc4b405c7f6384cd3cf89be0960a94929b3099e')
#a = v.info('75a2d61962f981834738df1e9b0a96f0')
#print(a['data'])

API_KEY = 'your_api_key_here'
MD5_HASH = 'your_md5_hash_here'

def check_md5(api_key, md5_hash):
    url = f'https://www.virustotal.com/api/v3/files/{md5_hash}'
    headers = {
        'x-apikey': api_key
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        json_response = response.json()
        scan_results = json_response['data']['attributes']['last_analysis_stats']
        if scan_results['malicious'] > 0:
            print(f"{md5_hash} is likely malicious.")
            print(f"Detection: {scan_results['malicious']} out of {scan_results['malicious'] + scan_results['undetected']} scanners.")
        else:
            print(f"{md5_hash} is not detected as malicious.")
    elif response.status_code == 404:
        print(f"{md5_hash} was not found in the VirusTotal database.")
    else:
        print(f"An error occurred: {response.status_code}")

check_md5('24610375250fa23e5dd6c6d72cc4b405c7f6384cd3cf89be0960a94929b3099e', '75a2d61962f981834738df1e9b0a96f0')