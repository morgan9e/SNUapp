import base64

key=SNU_ENC_KEY
raw = ""

rd = base64.b64decode(raw)

from Crypto.Cipher import AES 
from Crypto.Util.Padding import unpad

key = key.encode()
iv = b'\x00' * 16
cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted_data = cipher.decrypt(rd)
print(decrypted_data)