import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from datetime import datetime
import json

cipher = lambda: AES.new(SNU_ENC_KEY.encode(), AES.MODE_CBC, b'\x00' * 16)
dec = lambda x: unpad(cipher().decrypt(base64.b64decode(x)), AES.block_size, style='pkcs7')
enc = lambda x: base64.b64encode(cipher().encrypt(pad(x, AES.block_size, style='pkcs7')))

attend_url = ""

bleInfo = {
            CLASSROOM_ID:  (MAC, MAJ, MIN, RSSI, UUID),
          }
          
roomInfo = {LECTURE_ID: CLASSROOM_ID}

userId = STUDENT_ID
lectureId = LECTURE_ID
bleMac, bleMajor, bleMinor, bleRSSI, bleUUID = bleInfo[roomInfo[lectureId]]


timeCustom = datetime.strftime(datetime.now(), "%Y%m%d%H%M%S")
plainble = '[{"bleWorkEndTime":"","bleWorkStartTime":"","bleBattery":"0","bleMacAddress":"' + bleMac + '","bleMajor":"' + bleMajor + '","bleMinor":"' + bleMinor + '","bleRssi":"' + bleRSSI + '","bleSignalPeriod":"0","bleTxPower":"0","bleUuid":"' + bleUUID + '"}]_' + timeCustom + userId + lectureId
bleEnc = enc(plainble.encode()).decode()
plainbody = '{"bleList":null,"bleListEx":"' + bleEnc + '","classSort":"0","lectureId":"' + lectureId + '","userId":"' + userId + '","verifyNum":null,"verifyType":null,"yearTerm":"20241"}'
bodyhash = hashlib.sha1(plainbody.encode()).hexdigest()
plainheader = '{"appVer":VER,"authType":"0","deviceLocale":"ko_KR","deviceMac":"00:00:00:00:00:00","deviceModel":MODEL,"deviceType":TYPE,"deviceUuid":UUID,"deviceVer":"9","enc":"' + bodyhash + '","loginId":"' + userId + '","ssoToken":"","trId":"A002","trVer":"1.0.0","userId":""}'
encheader = enc(plainheader.encode()).decode()
reqbody = json.dumps({"header": encheader,"body": plainbody})

print(reqbody)

import requests

header = {
  "Accept-Language": "ko_KR",
  "User-Agent": "Android",
  "Host": "scard1.snu.ac.kr"
}

resp = requests.post(attend_url, json={ "header": encheader,"body": plainbody }, headers=header).json()
rh = dec(resp["header"]).decode()
rb = json.loads(resp["body"])

print(rh)
print(rb)