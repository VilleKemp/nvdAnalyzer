'''
Original source
https://avleonov.com/2017/10/03/downloading-and-analyzing-nvd-cve-feed/
'''

import requests
import re

r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
for filename in re.findall("nvdcve-1.0-[0-9]*\.json\.zip",r.text):
    print(filename)
    r_file = requests.get("https://static.nvd.nist.gov/feeds/json/cve/1.0/" + filename, stream=True)
    with open("json/" + filename, 'wb') as f:
        for chunk in r_file:
            f.write(chunk)
