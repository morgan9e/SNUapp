from mitmproxy import ctx
from mitmproxy import http
import json
import logging
import base64
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad

LOG=""

from datetime import datetime

cipher = lambda: AES.new(SNU_ENC_KEY.encode(), AES.MODE_CBC, b'\x00' * 16)
decraw = lambda x: unpad(cipher().decrypt(x), AES.block_size, style='pkcs7')
enc = lambda x: base64.b64encode(cipher().encrypt(pad(x, AES.block_size, style='pkcs7')))
encstr = lambda x: "".join([hex(i)[2:].zfill(2) for i in (cipher().encrypt(pad(x, AES.block_size, style='pkcs7')))])


def decrypt(raw):
    key=SNU_ENC_KEY
    rd = base64.b64decode(raw)
    key = key.encode()
    iv = b'\x00' * 16
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(rd)
    return decrypted_data

def gettime():
    return datetime.strftime(datetime.now(), "%H:%M:%S")

def response(flow: http.HTTPFlow) -> None:
    url = flow.request.pretty_url
    if url == "":
        data = json.loads(flow.response.get_text())
        data["VERSION"]["SIGN_KEY"] = MY_SIGN_KEY
        flow.response.text = json.dumps(data)
    elif ("" in url) and ("" not in url) and ("" not in url):
        req = json.loads(flow.request.get_text())
        data = json.loads(flow.response.get_text())
        with open(LOG, "a") as f:
            f.write(f"[{gettime()}] {flow.request.pretty_url}")
            f.write("\n\n-->\n\n")
            f.write(decrypt(req["header"]).decode())
            f.write("\n")
            f.write(req["body"])
            f.write("\n\n<--\n\n")
            f.write(decrypt(data["header"]).decode())
            f.write("\n")
            f.write(data["body"])
            f.write("\n\n")
    
    elif ("" in url) or ("" in url):
        req = json.loads(flow.request.get_text())
        data = json.loads(flow.response.get_text())
        with open(LOG, "a") as f:
            f.write(f"[{gettime()}] {flow.request.pretty_url}")
            f.write("\n\n-->\n\n")
            f.write( decraw(bytes.fromhex(req["header"])).decode() )
            f.write("\n")
            f.write( decraw(bytes.fromhex(req["body"])).decode() if req["body"] != "{}" else "{}" )
            f.write("\n\n<--\n\n")
            f.write( decraw(bytes.fromhex(data["header"])).decode() )
            f.write("\n")
            f.write( decraw(bytes.fromhex(data["body"])).decode() if data["body"] != "{}" else "{}" )
            f.write("\n\n")
    
def request(flow: http.HTTPFlow) -> None:
    url = flow.request.pretty_url
    logging.info(url)
    if ("" in url) or ("" in url):
        data = json.loads(flow.request.get_text())
        data["header"] = encstr((decraw(bytes.fromhex(data["header"])).decode().replace(SNU_SIGN_KEY,MY_SIGN_KEY).encode()).upper()
        flow.request.text = json.dumps(data)