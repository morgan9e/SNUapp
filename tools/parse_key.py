aaa = [""""""]

q = []
for a in aaa:
  a = [ i.split("          ")[1] for i in a.split("\n") if i]
  z = {}
  z["var_20"] = [0,0,0,0,0,0,0,0]
  z["var_28"] = [0,0,0,0,0,0,0,0]
  z["var_18"] = [0,0,0,0,0,0,0,0]
  z["var_30"] = [0,0,0,0,0,0,0,0]
  for i in a:
    b = i.split(" = ")
    if "[" not in b[0]:
      z[b[0]][0] = b[1].replace(";","") 
    else:
      z["var"+b[0].split("var")[1].split(")")[0]][int(b[0].split("[")[1].split("]")[0])] = b[1].replace(";","") 
  q.append(z)


for i in q:
  print("".join([ j[2:] for j in i["var_18"]]))
  print("".join([ j[2:] for j in i["var_20"]]))
  print("".join([ j[2:] for j in i["var_28"]]))
  print("".join([ j[2:] for j in i["var_30"]]))
  print()
# exit()
from datetime import datetime

date_str = ""
date_format = "%a, %d %b %Y %H:%M:%S GMT"
date_obj = datetime.strptime(date_str, date_format)
dtime = int(date_obj.timestamp())
print(dtime)
int32 = lambda x: (x-((x>>32)<<32))
l=((int32(((dtime+1)*0x2aaaaaab)>>32)>>1)-((dtime+1)>>31))
print(n:=((dtime+1)-(l<<4)-(l<<2)))

import base64
rd = base64.b64decode(rawstring)

for z in q:
  p = "".join(i[2:] for i in z["var_30"])
  q = "".join(i[2:] for i in z["var_18"])
  r = "".join(i[2:] for i in z["var_20"])
  s = "".join(i[2:] for i in z["var_28"])
  from Crypto.Cipher import AES 
  from Crypto.Util.Padding import unpad

  lbe = lambda x: "".join(reversed([ x[i]+x[i+1] for i in range(0, len(x), 2)]))
  for k in [p, q, r, s]:
    key = k.encode()
    iv = b'\x00' * 16
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(rd)
    print(decrypted_data)

    key = lbe(k).encode()
    iv = b'\x00' * 16
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(rd)
    print(decrypted_data)