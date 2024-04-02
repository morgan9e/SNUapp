import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

cipher = lambda: AES.new(SNU_ENC_KEY.encode(), AES.MODE_CBC, b'\x00' * 16)
dec = lambda x: unpad(cipher().decrypt(base64.b64decode(x)), AES.block_size, style='pkcs7')
enc = lambda x: base64.b64encode(cipher().encrypt(pad(x, AES.block_size, style='pkcs7')))

# decd = dec(org)

# print(decd)
# endd = enc(decd)

# for i,j in zip(endd.decode().replace("\n",""), org):
#   assert i == j

a = {
}

print(dec(a["header"]))

import requests, json

json = json.dumps({"body": body, "header": enc(header.encode()).decode().replace("\n","")})
print( enc(header.encode()) )

# req = requests.post(url="")
# print(req.text)