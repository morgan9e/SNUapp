import base64, hashlib, uuid, time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
import requests, json, sys
from secrets.params import SNU_ENC_KEY, SNU_APP_SIG
from secrets.params import urls, bleInfo, roomInfo

cipher = lambda: AES.new(SNU_ENC_KEY.encode(), AES.MODE_CBC, b'\x00' * 16)
dec = lambda x: unpad(cipher().decrypt(base64.b64decode(x)), AES.block_size, style='pkcs7')
decraw = lambda x: unpad(cipher().decrypt(x), AES.block_size, style='pkcs7')
decstr = lambda x: unpad(cipher().decrypt(bytes.fromhex(x)), AES.block_size, style='pkcs7')
enc = lambda x: base64.b64encode(cipher().encrypt(pad(x, AES.block_size, style='pkcs7')))
encstr = lambda x: "".join([hex(i)[2:].zfill(2) for i in (cipher().encrypt(pad(x, AES.block_size, style='pkcs7')))])

photo_url = urls.get("photo_url", "")
main_url = urls.get("main_url", "")
api_url = urls.get("api_url", "")
attend_url = urls.get("attend_url", "")
lecture_url = urls.get("lecture_url", "")
info_url = urls.get("info_url", "")

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

def getAttnData(userId):
  plainbody = '{"bleList":[],"pushToken":null,"userId":"'+ userId + '","userPw":null,"yearTerm":""}'
  bodyhash = hashlib.sha1(plainbody.encode()).hexdigest()
  plainheader = '{"appVer":"3.4.29","authType":"","deviceLocale":"ko_KR","deviceMac":"00:00:00:00:00:00","deviceModel":"' + DEVMODEL + '","deviceType":"10","deviceUuid":"' + DEVUUID + '","deviceVer":"9","enc":"' + bodyhash + '","loginId":"","ssoToken":"","trId":"A001","trVer":"1.0.0","userId":""}'
  encheader = enc(plainheader.encode()).decode()
  reqbody = json.dumps({"header": encheader,"body": plainbody})
  header = {
    "Accept-Language": "ko_KR",
    "User-Agent": "Android",
    "Host": "scard1.snu.ac.kr"
  }
  resp = requests.post(lecture_url, json={ "header": encheader,"body": plainbody }, headers=header)
  if resp.status_code != 200:
    raise Exception("Fetch Error.")
  rh = dec(resp.json()["header"]).decode()
  rb = json.loads(resp.json()["body"])
  print(rb)
  auth = "ble" if (rb["bleAttendYN"] == "Y") else ("code" if rb["verifyYN"] == "Y" else "no")
  return { "day": rb["day"], "room": rb["bleRoomCd"], "roomname": rb["bleRoomNm"].split("] ")[1], "lectureId": rb["lectureId"], "auth": auth, "status": rb["attendStatus"], "raw": rb }
    
def doAttend(userId, lectureId):
  bleMac, bleMajor, bleMinor, bleRSSI, bleUUID = bleInfo[roomInfo[lectureId]]
  timeCustom = datetime.strftime(datetime.now(), "%Y%m%d%H%M%S")
  plainble = '[{"bleWorkEndTime":"","bleWorkStartTime":"","bleBattery":"0","bleMacAddress":"' + bleMac + '","bleMajor":"' + bleMajor + '","bleMinor":"' + bleMinor + '","bleRssi":"' + bleRSSI + '","bleSignalPeriod":"0","bleTxPower":"0","bleUuid":"' + bleUUID + '"}]_' + timeCustom + userId + lectureId
  bleEnc = enc(plainble.encode()).decode()
  plainbody = '{"bleList":null,"bleListEx":"' + bleEnc + '","classSort":"0","lectureId":"' + lectureId + '","userId":"' + userId + '","verifyNum":null,"verifyType":null,"yearTerm":"20241"}'
  bodyhash = hashlib.sha1(plainbody.encode()).hexdigest()
  plainheader = '{"appVer":"3.4.29","authType":"0","deviceLocale":"ko_KR","deviceMac":"00:00:00:00:00:00","deviceModel":"'+DEVMODEL+'","deviceType":"10","deviceUuid":"'+DEVUUID+'","deviceVer":"9","enc":"' + bodyhash + '","loginId":"' + userId + '","ssoToken":"","trId":"A002","trVer":"1.0.0","userId":""}'
  encheader = enc(plainheader.encode()).decode()
  reqbody = json.dumps({"header": encheader,"body": plainbody})
  header = {
    "Accept-Language": "ko_KR",
    "User-Agent": "Android",
    "Host": "scard1.snu.ac.kr"
  }

  resp = requests.post(attend_url, json={ "header": encheader,"body": plainbody }, headers=header).json()
  if resp.status_code != 200:
    raise Exception("Fetch Error.")
  rh = dec(resp["header"]).decode()
  rb = json.loads(resp["body"])
  print(rb)

def doId(userId, userAccount):
  initStatus = ("initStatus", '{}')
  initStaHdr = lambda MSGCD: '{"appKey":"'+SNU_APP_SIG+'","appVer":"3.4.29","deviceModel":"'+DEVMODEL+'","deviceUuid":"'+DEVUUID.replace("-","").lower()+'","deviceVer":"9","enc":"bf21a9e8fbc5a3846fb05b4fa0859e0917b2202f","msgCd":"initStatus","osType":"A","requestTime":"'+datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S.%f")[:-3]+'","trVer":"1.0.0","transactionId":"'+str(uuid.uuid4()).upper().replace("-","")+'"}'

  g_reqCreatQR = lambda issueNo: ("IFIDT006", '{"issueNo":"'+issueNo+'","ssoToken":null,"userId":"'+userId+'"}')
  reqInqCard = ("IFIDT010", '{"phoneNumber":"'+PHONENUM+'","ssoToken":null,"uiccId":"'+DEVUUID.replace("-","").lower()+'","userAccount":"'+userAccount+'","userId":"'+userId+'"}')
  regMobCard = ("IFIDT011", '{"phoneNumber":"'+PHONENUM+'","ssoToken":null,"uiccId":"'+DEVUUID.replace("-","").lower()+'","userAccount":"'+userAccount+'","userId":"'+userId+'"}')
  mobCardHdr = lambda MSGCD: '{"appKey":"'+SNU_APP_SIG+'","appVer":"3.4.29","deviceModel":"'+DEVMODEL+'","deviceUuid":"'+DEVUUID.replace("-","").lower()+'","deviceVer":"9","msgCd":"'+MSGCD+'","osType":"A","requestTime":"'+datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S.%f")[:-3]+'","trVer":"1.0.0","transactionId":"'+str(uuid.uuid4()).upper().replace("-","").lower()+'"}'

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


if __name__=="__main__":
  CLI=True

  if CLI:
    import sys
    if len(sys.argv) < 3:
      print("Usage: snu.py [attend/id] [SNU_ID]")
      exit()
    userAccount = sys.argv[2]
    cmd = sys.argv[1]
  else:
    userAccount = ""
    cmd = ""

  if cmd not in ["attend", "id"]:
    print("Usage: snu.py [attend/id] [SNU_ID]")
    exit()  

  if not userAccount:
    raise Exception("userAccount empty.")

  resp = requests.post(info_url, json={"SNU":[{"sa_uid":userAccount}]})
  if resp.status_code != 200:
    raise Exception("Fetch Error")

  print(user_info := resp.json())
  userId = user_info["REQ_DATA"].get("rpstPersNo")
  userAccount = userAccount

  if not userId:
    raise Exception("userId empty.")

  if cmd == "attend":
    attndata = getAttnData(userId)
    if attndata["room"] not in bleInfo:
      raise Exception("BLE Beacon Info not registered.")
    if attndata["lectureId"] not in roomInfo:
      raise Exception("Classroom Info not registered.")
    if attndata["status"] == "미인증":
      raise Exception("Cant do attendance yet.")
    if attndata["auth"] != "ble":
      raise Exception("Only Beacon based attendance is supported.")
    doAttend(userId, attndata["lectureId"])

  elif cmd == "id":
    doId(userId, userAccount)
    print("Saved QR and Profile. QR is only eligible for 3 minutes.")