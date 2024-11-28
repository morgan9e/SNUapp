#!/usr/bin/env python3

import uuid
import requests
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime

from postech_param import (
    POS_APP_SIG,
    POS_ENC_KEY,
    APP_VER,
    DEV_MODEL,
    DEV_UUID,
    UA,
    IDT_URL,
    MSS_URL,
)


def cipher(x):
    return AES.new(x, AES.MODE_ECB)


def encraw(k, x):
    return cipher(k).encrypt(pad(x, AES.block_size))


def encstr(k, x):
    return "".join([hex(i)[2:].zfill(2) for i in encraw(k, x)])


def getDate():
    return datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S.%f")[:-3]


def genUUID():
    return str(uuid.uuid4()).replace("-", "")


def AbstractAPIProtocol(MSGCD, body: dict):
    def getSessionKey(trId, encKey) -> bytes:
        secret_key_spec = AES.new(encKey.encode(), AES.MODE_ECB).encrypt(
            pad((trId + encKey).encode(), AES.block_size)
        )
        return secret_key_spec[:16]

    def genReqHdr(MSGCD, trId):
        return {
            "appKey": POS_APP_SIG,
            "appVer": APP_VER,
            "deviceModel": DEV_MODEL,
            "deviceUuid": DEV_UUID.replace("-", "").lower(),
            "deviceVer": "9",
            "msgCd": MSGCD,
            "osType": "A",
            "requestTime": getDate(),
            "trVer": "1.0.0",
            "transactionId": trId,
        }

    trId = genUUID()
    reqHdr = genReqHdr(MSGCD, trId)
    encKey = getSessionKey(trId, POS_ENC_KEY)
    plainReqBody = json.dumps(body)
    reqBody = encstr(encKey, plainReqBody.encode())
    realBody = {"header": reqHdr, "body": reqBody}
    realHdr = {
        "user-agent": UA,
        "content-type": "application/json; charset=UTF-8",
    }
    print(realBody, realHdr)
    resp = requests.post(IDT_URL, json=realBody, headers=realHdr)
    resp_json = resp.json()
    resp_body = resp_json["body"]
    resp = unpad(
        cipher(encKey).decrypt(bytes.fromhex(resp_body)), AES.block_size
    ).decode()
    data = json.loads(resp)
    return data


def IFT():
    resp = AbstractAPIProtocol("IFIDT001", {"userId": userId})

    resp = AbstractAPIProtocol(
        "IFIDT021",
        {"userId": userId, "userAccount": userAccount, "cardTypeCd": cardTypeCd},
    )

    resp = AbstractAPIProtocol(
        "IFIDT022",
        {"userId": userId, "userAccount": userAccount, "issueReqNo": issueReqNo},
    )

    resp = AbstractAPIProtocol(
        "IFIDT023",
        {"userId": userId, "userAccount": userAccount, "userName": userName},
    )

    resp = AbstractAPIProtocol(
        "IFIDT030",
        {"userId": userId, "email": email, "phoneMobile": phoneMobile},
    )

    resp = AbstractAPIProtocol(
        "IFIDT031",
        {
            "userId": userId,
            "email": email,
            "phoneMobile": phoneMobile,
            "cardTypeCd": cardTypeCd,
        },
    )

    resp = AbstractAPIProtocol(
        "IFIDT032",
        {
            "userId": userId,
            "email": email,
            "phoneMobile": phoneMobile,
            "issueReqNo": issueReqNo,
        },
    )

    resp = AbstractAPIProtocol(
        "IFIDT033",
        {
            "userId": userId,
            "email": email,
            "phoneMobile": phoneMobile,
            "cardIssueNo": cardIssueNo,
        },
    )

    resp = AbstractAPIProtocol(
        "IFIDT034",
        {
            "userId": userId,
            "phoneMobile": phoneMobile,
            "authCode": authCode,
        },
    )

    # userId, collegeName, collegeNameE, departmentName, departmentNameE, majorName, majorNameE, positionName, positionNameE, userTypeCd, userTypeName, userName, userNameE, effectiveDt, expirationDt, userPhoto, list
    # issueReqNo, userId, orgCd, orgName, univCd, campusCd, issueType, cardIssueNo, userName, issueToken, derivedUserKey, spayYn, rfu
    # cardId, cardTypeCd, cardKindCd, cardStateCd, cardIssueNo, userId, userTypeCd, userTypeName, userName, userNameE, collegeName, collegeNameE, departmentName, departmentNameE, majorName, majorNameE, positionName, positionNameE
    # jwtData
    # userId, collegeName, collegeNameE, userTypeCd, userTypeName, userName, email, effectiveDt, expirationDt, agreeYn, list, cardId, cardIssueNo, cardTypeCd, cardKindCd, cardStateCd
    # issueReqNo, userId, orgCd, orgName, univCd, campusCd, issueType, cardIssueNo, userName, issueToken, derivedUserKey, rfu
    # cardId, cardTypeCd, cardKindCd, cardStateCd, cardIssueNo, userId, userTypeCd, userTypeName, userName, email
    # userId, qrCode, qrCodeIssueTime, expiresIn
    # userId, email, phoneMobile

    print(resp)


def MSS():
    userAccount = ""

    reqHdr = {
        "user-agent": UA,
        "content-type": "application/json; charset=UTF-8",
    }

    reqBody = {
        "header": {
            "msgCd": "IFMSS011",
            "msgType": "0200",
            "systemCd": "MSS",
            "reqTime": datetime.strftime(datetime.now(), "%Y%m%d%H%M%S%f")[:-3],
        },
        "body": {
            "os": "1",
            "uuid": DEV_UUID.replace("-", "").lower(),
            "userAccount": userAccount,
        },
    }

    resp = requests.post(MSS_URL, json=reqBody, headers=reqHdr)
    resp_json = json.loads(resp.text)
    USER_INFO = resp_json["body"]
    print(USER_INFO)


# IFT()
MSS()
