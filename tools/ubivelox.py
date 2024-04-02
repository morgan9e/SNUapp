import os, sys
import re, string

FILE = "libEncryptionKeyStore.so"

def vb(ba, offset = 0, split = 8):  
  def p(ba, addr):
    bns, chs = "", ""
    bn = [f"{hex(i)[2:]:>02}" for i in ba]
    ch = [chr(i) if chr(i) in string.printable else "." for i in ba]
    for i in range(0,len(ba),split):
      for j in range(split):
        bns += (bn[i+j] if i+j < len(ba) else "  ") + " "
        chs += (ch[i+j] if i+j < len(ba) else "  ")
    return f"{hex(addr)[2:]:>08} | {bns} | {chs}"
  for i in range(0, len(ba), split):
    print(p(ba[i:min(len(ba),i+split)], offset+split*i))

with open(FILE, "rb") as f:
  fdata = f.read()

# print(len(fdata))
loc = 0x7d84
# print()
# vb(fdata[loc:loc+256], offset=loc)
# print()

import armv8
bebinstr = lambda raw: ''.join(reversed([bin(raw)[2:].zfill(32)[i:i+8] for i in range(0, len(bin(raw)[2:].zfill(32)), 8)]))
binstr = lambda raw: bin(raw)[2:].zfill(32)

def parse(start, end):
  res = []
  for i in range(start, end, 4):
    opcode = hex(fdata[i])[2:].zfill(2) + hex(fdata[i+1])[2:].zfill(2) + hex(fdata[i+2])[2:].zfill(2) + hex(fdata[i+3])[2:].zfill(2)
    asm = armv8.find(binstr(int.from_bytes(bytearray.fromhex(opcode), byteorder='little', signed=False)))
    res.append((i, opcode, asm))
  return res

def modify_movz(o, i, d):
  t = "x10x00101xxiiiiiiiiiiiiiiiiddddd"
  n = ["" for _ in range(32)]
  ib, db = bin(i)[2:][-16:].zfill(16), bin(d)[2:][-5:].zfill(5)
  ix, dx = 0, 0
  for i in range(32):
    if t[i] in "x01":
      n[i] = o[i]
    elif t[i] in "i":
      n[i] = ib[ix]
      ix += 1
    elif t[i] in "d":
      n[i] = db[dx]
      dx += 1
    else:
      print("e", i)
      return
  return "".join(n)

binStrFromAddr = lambda i: binstr(int.from_bytes(bytearray.fromhex(hex(fdata[i])[2:].zfill(2) + hex(fdata[i+1])[2:].zfill(2) + hex(fdata[i+2])[2:].zfill(2) + hex(fdata[i+3])[2:].zfill(2)), byteorder='little', signed=False))
lhex = lambda x: "0x"+"".join(list(reversed([s[i]+s[i+1] for i in range(0,len(s),2)] if (s := hex(x)[2:]) else [])))
f = lambda hexstr: "".join([chr(i) for i in bytearray.fromhex(hexstr)])
t = lambda cert: [ord(i) for i in cert]
t2 = lambda cert: "".join([hex(ord(i))[2:] for i in cert])
pt = lambda cert: " ".join([hex(ord(i)) for i in cert])
pt2 = lambda cert: "\n".join([ f"+0x{hex(i)[2:]:>02} --> {hex(ord(j))}" for i, j in enumerate(cert)])

# MAIN JOB

res = parse(0x7d64, 0x81d4)

n = 0
w = [0 for _ in range(0x32)]
wl = [0 for _ in range(0x32)]
x = ["" for _ in range(0x32)]
xl = [0 for _ in range(0x32)]
while n < len(res):
  if res[n][2][0] == "movz Rd HALF":
    # print(hex(res[n][0]), res[n][2])
    w[res[n][2][1]['d']] = res[n][2][1]['i']
    wl[res[n][2][1]['d']] = res[n][0]
  if res[n][2][0] == "strb Rt ADDR_UIMM12":
    # print(hex(res[n][0]), res[n][2])
    x[res[n][2][1]['i']] = w[res[n][2][1]['t']]
    xl[res[n][2][1]['i']] = wl[res[n][2][1]['t']]
  n += 1

# print()
oldsig = ""
for i in range(len(x)):
  if x[i]:
    oldsig += hex(int(x[i]))[2:]
    # print(hex(xl[i]), "->", hex(int(x[i])))
  else:
    break
# print()

nss = MY_SIGN_KEY
ns = t(nss)
print(oldsig)
print(t2(nss))
print()
xls = [xl[n] for n, i in enumerate(x) if i]
assert len(ns) == len(xls)

nd = list(fdata)

for x, a in enumerate(xls):
  o = binStrFromAddr(a)
  i, d = armv8.find(o)[1]['i'], armv8.find(o)[1]['d']
  i = ns[x]
  n = modify_movz(o,i,d)
  assert len(fdata[a:a+4]) == len(b := bytearray.fromhex(lhex(int(n,2))[2:]))
  nd[a:a+4] = b
  print(f"[{hex(a)}]" + " 0x"+"".join([hex(i)[2:].zfill(2) for i in fdata[a:a+4]]) + " -> " + lhex(int(n,2)))

res = parse(0x81d8, 0x82cc)

n = 0
w = [0 for _ in range(0x32)]
wl = [0 for _ in range(0x32)]
x = ["" for _ in range(0x32)]
xl = [0 for _ in range(0x32)]
while n < len(res):
  if res[n][2][0] == "movz Rd HALF":
    # print(hex(res[n][0]), res[n][2])
    w[res[n][2][1]['d']] = res[n][2][1]['i']
    wl[res[n][2][1]['d']] = res[n][0]
  if res[n][2][0] == "strb Rt ADDR_UIMM12":
    # print(hex(res[n][0]), res[n][2])
    x[res[n][2][1]['i']] = w[res[n][2][1]['t']]
    xl[res[n][2][1]['i']] = wl[res[n][2][1]['t']]
  n += 1

for x, a in enumerate(xl):
  if not a:
    continue
  o = binStrFromAddr(a)
  i, d = armv8.find(o)[1]['i'], armv8.find(o)[1]['d']
  i = ns[x]
  n = modify_movz(o,i,d)
  assert len(fdata[a:a+4]) == len(b := bytearray.fromhex(lhex(int(n,2))[2:]))
  nd[a:a+4] = b
  print(f"[{hex(a)}]" + " 0x"+"".join([hex(i)[2:].zfill(2) for i in fdata[a:a+4]]) + " -> " + lhex(int(n,2)))

res = parse(0x831c, 0x840c)

n = 0
w = [0 for _ in range(0x32)]
wl = [0 for _ in range(0x32)]
x = ["" for _ in range(0x32)]
xl = [0 for _ in range(0x32)]
while n < len(res):
  if res[n][2][0] == "movz Rd HALF":
    # print(hex(res[n][0]), res[n][2])
    w[res[n][2][1]['d']] = res[n][2][1]['i']
    wl[res[n][2][1]['d']] = res[n][0]
  if res[n][2][0] == "strb Rt ADDR_UIMM12":
    # print(hex(res[n][0]), res[n][2])
    x[res[n][2][1]['i']] = w[res[n][2][1]['t']]
    xl[res[n][2][1]['i']] = wl[res[n][2][1]['t']]
  n += 1

for x, a in enumerate(xl):
  if not a:
    continue
  o = binStrFromAddr(a)
  i, d = armv8.find(o)[1]['i'], armv8.find(o)[1]['d']
  i = ns[x]
  n = modify_movz(o,i,d)
  assert len(fdata[a:a+4]) == len(b := bytearray.fromhex(lhex(int(n,2))[2:]))
  nd[a:a+4] = b
  print(f"[{hex(a)}]" + " 0x"+"".join([hex(i)[2:].zfill(2) for i in fdata[a:a+4]]) + " -> " + lhex(int(n,2)))


print()
nd = bytes(nd)
mb = 0
for i in range(len(fdata)):
  if fdata[i] != nd[i]:
    mb += 1
print(f"Modified {mb} bytes.") 

(print(f"File {FILE+".mod"} already exists") + exit()) if os.path.exists(FILE+".mod") else 0
with open(FILE+".mod", "wb") as f:
  f.write(nd)
print(f"Saved to {FILE+".mod"}")