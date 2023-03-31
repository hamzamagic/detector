import requests
import volatility3.framework.plugins.windows.pslist
# from requests.api import request
import volatility3.framework as vf
# from volatility3.framework import exceptions, renderers, interfaces
# from volatility3.framework.configuration import requirements
# from volatility3.framework.renderers import format_hints
# from volatility3.plugins import windows
# from virusshare import VirusShare

# API key: '24610375250fa23e5dd6c6d72cc4b405c7f6384cd3cf89be0960a94929b3099e'
# example of MD5: '75a2d61962f981834738df1e9b0a96f0'

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

# The two functions below need to be double-checked
def get_pslist_data(self):
    # Instantiate the PsList plugin
    pslist_plugin = vf.plugins.windows.pslist.PsList(self._config)

    # Call the calculate method of the PsList plugin
    pslist_data = pslist_plugin.calculate()

    # Return the data from the PsList plugin
    return pslist_data

def render_text(self, outfd, data):
    pslist_data = self.get_pslist_data()

    # Process the pslist_data
    for task in pslist_data:
        process_name = task.ImageFileName
        process_id = task.UniqueProcessId
        outfd.write(f"Process Name: {process_name}, Process ID: {process_id}\n")


check_md5(API_KEY, MD5_HASH)