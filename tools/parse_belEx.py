import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

cipher = lambda: AES.new(SNU_ENC_KEY.encode(), AES.MODE_CBC, b'\x00' * 16)
dec = lambda x: unpad(cipher().decrypt(base64.b64decode(x)), AES.block_size, style='pkcs7')
enc = lambda x: base64.b64encode(cipher().encrypt(pad(x, AES.block_size, style='pkcs7')))

print(D := dec(A))
assert enc(D).decode() == "".join([ i for i in enc(D).decode()])
# print(hashlib.sha1(raw["body"].encode()).hexdigest())
# import json
# print(hashlib.sha1(raw["body"].encode()).hexdigest())

rlbody = ''
print(hashlib.sha1(rlbody.encode()).hexdigest())

# reqAttendCertificateForStu.setBleListEx(Base64.encodeToString(z6.a.encryptTextandKey(new com.google.gson.e().t(reqAttendCertificateForStu.getBleList()) + "_" + e6.a.yyyyMMddHHmmss(System.currentTimeMillis()) + reqAttendCertificateForStu.getUserId() + reqAttendCertificateForStu.getLectureId(), this.f14530g.secretKeyEx()), 2));

# [
#   { 
#     "bleWorkEndTime":"",
#     "bleWorkStartTime":"",
#     "bleBattery":"0",
#     "bleMacAddress":"MAC",
#     "bleMajor":"MAJ",
#     "bleMinor":"MIN",
#     "bleRssi":"RSSI",
#     "bleSignalPeriod":"0",
#     "bleTxPower":"0",
#     "bleUuid":"UUID"
#   }
# ]
# + "_" + TIME + ID + LEC