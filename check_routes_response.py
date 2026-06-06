import urllib.request
paths = ['/', '/login', '/register', '/dashboard']
for path in paths:
    url = 'http://127.0.0.1:5000' + path
    try:
        resp = urllib.request.urlopen(url)
        data = resp.read(300).decode('utf-8', 'ignore')
        print('PATH', path, 'STATUS', resp.status)
        print(data.replace('\n', ' ')[:200])
    except Exception as e:
        print('PATH', path, 'ERROR', repr(e))
