import urllib.request
url = 'http://127.0.0.1:5000/register'
try:
    resp = urllib.request.urlopen(url)
    print('STATUS', resp.status)
    print(resp.read(200).decode('utf-8', 'ignore'))
except Exception as e:
    print('ERROR', repr(e))
