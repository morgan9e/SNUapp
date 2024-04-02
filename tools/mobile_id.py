import base64, hashlib, uuid, time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
import requests, json

cipher = lambda: AES.new(SNU_ENC_KEY.encode(), AES.MODE_CBC, b'\x00' * 16)
dec = lambda x: unpad(cipher().decrypt(base64.b64decode(x)), AES.block_size, style='pkcs7')
decraw = lambda x: unpad(cipher().decrypt(x), AES.block_size, style='pkcs7')
decstr = lambda x: unpad(cipher().decrypt(bytes.fromhex(x)), AES.block_size, style='pkcs7')
enc = lambda x: base64.b64encode(cipher().encrypt(pad(x, AES.block_size, style='pkcs7')))
encstr = lambda x: "".join([hex(i)[2:].zfill(2) for i in (cipher().encrypt(pad(x, AES.block_size, style='pkcs7')))])

APPSIG = SNU_APP_SIG

DEVUUID = str(uuid.uuid4()).upper()
DEVMODEL = str(uuid.uuid4()).split("-")[1].upper()
PHONENUM = "01000000000"

def getReqBody(plainbody, getheader):
  if type(plainbody) == tuple:
    msgCd, plainbody = plainbody
    plainheader = getheader(msgCd)
    encheader = encstr(plainheader.encode()).upper()
    if msgCd != "initStatus":
      plainbody = encstr(plainbody.encode()).upper()

  elif type(plainbody) == str:
    bodyhash = hashlib.sha1(plainbody.encode()).hexdigest()
    plainheader = getheader(bodyhash)
    encheader = enc(plainheader.encode()).decode()

  print(plainheader, plainbody)
  return {"header": encheader,"body": plainbody}

def doReq(url, reqbody):
  reqheader = {
    "Accept-Language": "ko_KR",
    "User-Agent": "Android",
    "Host": "scard1.snu.ac.kr"
  }
  resp = requests.post(url, json=reqbody, headers=reqheader)
  if resp.status_code != 200:
    raise Exception("Fetch failed.")
  return resp.json()

  rh = dec(resp.json()["header"]).decode()
  rb = json.loads(resp.json()["body"])
  print(rh)
  print(rb)

##############

CLI=False

if CLI:
  import sys
  if len(sys.argv) != 2:
    print("Error.")
    exit()
  userAccount = sys.argv[1]
else:
  userAccount = ""

if not userAccount:
  raise Exception("Input empty.")

resp = requests.post("", json={"SNU":[{"sa_uid":userAccount}]})
if resp.status_code != 200:
  raise Exception("Fetch Error")

print(user_info := resp.json())
userId = user_info["REQ_DATA"].get("rpstPersNo")
userAccount = userAccount

##############

initStatus = ("initStatus", '{}')
initStaHdr = lambda MSGCD: '{"appKey":"'+APPSIG+'","appVer":"3.4.29","deviceModel":"'+DEVMODEL+'","deviceUuid":"'+DEVUUID.replace("-","").lower()+'","deviceVer":"9","enc":"bf21a9e8fbc5a3846fb05b4fa0859e0917b2202f","msgCd":"initStatus","osType":"A","requestTime":"'+datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S.%f")[:-3]+'","trVer":"1.0.0","transactionId":"'+str(uuid.uuid4()).upper().replace("-","")+'"}'

g_reqCreatQR = lambda issueNo: ("IFIDT006", '{"issueNo":"'+issueNo+'","ssoToken":null,"userId":"'+userId+'"}')
reqInqCard = ("IFIDT010", '{"phoneNumber":"'+PHONENUM+'","ssoToken":null,"uiccId":"'+DEVUUID.replace("-","").lower()+'","userAccount":"'+userAccount+'","userId":"'+userId+'"}')
regMobCard = ("IFIDT011", '{"phoneNumber":"'+PHONENUM+'","ssoToken":null,"uiccId":"'+DEVUUID.replace("-","").lower()+'","userAccount":"'+userAccount+'","userId":"'+userId+'"}')
mobCardHdr = lambda MSGCD: '{"appKey":"'+APPSIG+'","appVer":"3.4.29","deviceModel":"'+DEVMODEL+'","deviceUuid":"'+DEVUUID.replace("-","").lower()+'","deviceVer":"9","msgCd":"'+MSGCD+'","osType":"A","requestTime":"'+datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S.%f")[:-3]+'","trVer":"1.0.0","transactionId":"'+str(uuid.uuid4()).upper().replace("-","").lower()+'"}'

doAttend = '{"bleList":[],"pushToken":null,"userId":"'+ userId + '","userPw":null,"yearTerm":""}'
attndHdr = lambda bodyhash: '{"appVer":"3.4.29","authType":"","deviceLocale":"ko_KR","deviceMac":"00:00:00:00:00:00","deviceModel":"' + DEVMODEL + '","deviceType":"10","deviceUuid":"' + DEVUUID + '","deviceVer":"9","enc":"' + bodyhash + '","loginId":"","ssoToken":"","trId":"A001","trVer":"1.0.0","userId":""}'

##############

print("-->")
reqbody = getReqBody(initStatus, initStaHdr)
print()
print(reqbody)
print()
resp = doReq(main_url, reqbody)
print(f"<--\n{resp}")
print()
print(init_hdr := decraw(bytes.fromhex(resp["header"])).decode())
print(init_bdy := decraw(bytes.fromhex(resp["body"])).decode() if resp["body"] != "{}" else "{}")
print()
time.sleep(1)
print()
print("-->")
reqbody = getReqBody(reqInqCard, mobCardHdr)
print()
print(reqbody)
print()
resp = doReq(api_url, reqbody)
print(f"<--\n{resp}")
print()
print(inq_hdr := decraw(bytes.fromhex(resp["header"])).decode())
print(inq_bdy := decraw(bytes.fromhex(resp["body"])).decode() if resp["body"] != "{}" else "{}")
print()
time.sleep(1)
print()
print("-->")
reqbody = getReqBody(regMobCard, mobCardHdr)
print()
print(reqbody)
print()
resp = doReq(api_url, reqbody)
print(f"<--\n{resp}")
print()
print(rg_hdr := decraw(bytes.fromhex(resp["header"])).decode())
print(rg_bdy := decraw(bytes.fromhex(resp["body"])).decode() if resp["body"] != "{}" else "{}")
print()
time.sleep(1)
print()
print("-->")
reqbody = getReqBody(g_reqCreatQR(str(json.loads(rg_bdy)["list"][0]["cardIssueNo"])), mobCardHdr)
print()
print(reqbody)
print()
resp = doReq(api_url, reqbody)
print(f"<--\n{resp}")
print()
print(qr_hdr := decraw(bytes.fromhex(resp["header"])).decode())
print(qr_bdy := decraw(bytes.fromhex(resp["body"])).decode() if resp["body"] != "{}" else "{}")
print()
print()

print(json.loads(rg_bdy)["list"])

import qrcode
id_qr = qrcode.make(json.loads(qr_bdy)["qrCd"])
id_qr_date = json.loads(qr_bdy)["issueDt"]
id_qr.save(f"{userId}_{id_qr_date}.png")

UID = encstr(userId.encode()).upper()
req = requests.get(f"{photo_url}{UID}", headers={"User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; WayDroid x86_64 Device Build/RQ3A.211001.001)","Host": "scard1.snu.ac.kr","Connection": "Keep-Alive","Accept-Encoding": "gzip"})
with open(f'{userId}_profile.png', "wb") as f:
  f.write(req.content)

id_qr.show()