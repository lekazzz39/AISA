import pandas as pd
import requests as req

url_login = r'https://staff.timeweb.net/login'
url_main = r'https://staff.timeweb.net/oldstaff/load?module=mod_black_list&action=loadModule#1'
 
payload = {
    'LoginForm[username]': 'e.soskov',
    'LoginForm[password]': 'cIzv5WzH65N2',
}
 
headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3',
    'Connection': 'keep-alive',
    'Host': 'staff.timeweb.net',
    'X-Requested-With': 'XMLHttpRequest'
}
 
 
r = req.post(url_login, data=payload, headers=headers)
 
cookies = r.cookies.get_dict()
cookies['_identity'] = '48c580fececa1d74fbe78b00d96193517202b124718084523ae297f4628e5da0a%3A2%3A%7Bi%3A0%3Bs%3A9%3A%22_identity%22%3Bi%3A1%3Bs%3A60%3A%22%5B%22e.soskov%22%2C%226390ebc5-5e06-45e9-a501-97cbd6f50f72%22%2C62208000%5D%22%3B%7D'
 
r2 = req.get(url_main, cookies=cookies, headers=headers)
 
print(r2.status_code)
print(r2.url)
print(r2.text)