#!/usr/bin/env python3
"""Send an SMS via the TP-Link TL-MR6400 web API."""
import argparse
import base64
import hashlib
import os
import re
import time

import requests
from Crypto.Cipher import AES
from dotenv import load_dotenv


def aes_encrypt(plaintext: str, key: str, iv: str) -> str:
    """AES-128-CBC + PKCS7 --> Base64 string."""
    data = plaintext.encode()
    pad  = 16 - len(data) % 16
    data += bytes([pad]) * pad
    return base64.b64encode(AES.new(key.encode(), AES.MODE_CBC, iv.encode()).encrypt(data)).decode()


def aes_decrypt(ct_b64: str, key: str, iv: str) -> str:
    """AES-128-CBC --> plaintext string."""
    raw = AES.new(key.encode(), AES.MODE_CBC, iv.encode()).decrypt(base64.b64decode(ct_b64))
    return raw[:-raw[-1]].decode(errors="replace")


def rsa_encrypt(message: str, nn_hex: str, ee_hex: str) -> str:
    """
    Raw (no-padding) RSA matching the router's JS encrypt.js nopadding()/flag=0:
    split into 64-byte chunks, zero-pad right, compute c = m^e mod n per chunk.
    """
    n, e, ks = int(nn_hex, 16), int(ee_hex, 16), len(nn_hex) // 2
    return "".join(
        format(pow(int.from_bytes(message[i:i + ks].encode().ljust(ks, b"\x00")), e, n), f"0{ks * 2}x")
        for i in range(0, len(message), ks)
    )


class TLMR6400:
    def __init__(self, ip: str):
        self.url     = f"http://{ip}"
        self.session = requests.Session()
        self.session.cookies.set("loginErrorShow", "1")  # required for token injection into post-login page

        # populated by login()
        self.nn      = ""  # RSA modulus (hex)
        self.ee      = ""  # RSA exponent (hex)
        self.seq     = 0   # sequence number from /cgi/getParm
        self.aes_key = ""  # AES key (one-time, generated at login)
        self.aes_iv  = ""  # AES IV  (one-time, generated at login)
        self.pw_hash = ""  # MD5("admin" + password), set by login()

    def _request(self, method: str, path: str, **kw) -> requests.Response:
        """All requests need Referer to pass the router's CSRF check."""
        r = self.session.request(method, self.url + path, headers={"Referer": self.url + "/"}, **kw)
        r.raise_for_status()
        return r

    def login(self, password: str) -> None:
        self.pw_hash = hashlib.md5(("admin" + password).encode()).hexdigest()

        # 1. Prime the session cookie
        self._request("GET", "/", timeout=5)

        # 2. Fetch RSA public key + sequence number
        r = self._request("POST", "/cgi/getParm", timeout=5)
        self.nn  = re.search(r'nn="([0-9a-fA-F]+)"', r.text).group(1)
        self.ee  = re.search(r'ee="([0-9a-fA-F]+)"', r.text).group(1)
        self.seq = int(re.search(r'seq="?([0-9]+)', r.text).group(1))

        # 3. Check busy state (required by the router's login flow)
        self._request("POST", "/cgi/getBusy", timeout=5)

        # 4. Generate a one-time AES key + IV
        self.aes_key = os.urandom(8).hex()
        self.aes_iv  = os.urandom(8).hex()
        data_ct      = aes_encrypt(f"admin\n{password}", self.aes_key, self.aes_iv)

        # 5. RSA-sign: key=<k>&iv=<iv>&h=<MD5(admin+pwd)>&s=<seq + len(data_ct)>
        sign_plain = f"key={self.aes_key}&iv={self.aes_iv}&h={self.pw_hash}&s={self.seq + len(data_ct)}"
        sign_hex   = rsa_encrypt(sign_plain, self.nn, self.ee)

        # 6. POST login - base64 = and + must be percent-encoded in the query string
        data_enc = data_ct.replace("=", "%3D").replace("+", "%2B")
        r = self._request("POST", f"/cgi/login?data={data_enc}&sign={sign_hex}&Action=1&LoginStatus=0", timeout=5)
        if "$.ret=0" not in r.text:
            raise RuntimeError(f"Login failed: {r.text.strip()!r}")

        # 7. Extract the CSRF token from the post-login page JS
        r = self._request("GET", "/", timeout=5)
        m = re.search(r'var\s+token\s*=\s*["\']([0-9a-fA-F]+)["\']', r.text)
        if not m:
            raise RuntimeError("Could not find token in post-login page.")
        self.session.headers.update({"TokenID": m.group(1), "Content-Type": "text/plain"})

    def _cgi_gdpr(self, plaintext: str) -> str:
        """Encrypt plaintext, POST to /cgi_gdpr, return decrypted response."""
        data_ct  = aes_encrypt(plaintext, self.aes_key, self.aes_iv)
        sign_hex = rsa_encrypt(f"h={self.pw_hash}&s={self.seq + len(data_ct)}", self.nn, self.ee)
        r = self._request("POST", "/cgi_gdpr",
                          data=f"sign={sign_hex}\r\ndata={data_ct}\r\n",
                          timeout=10)
        return aes_decrypt(r.text.strip(), self.aes_key, self.aes_iv)

    def send_sms(self, phone: str, message: str) -> None:
        # Strip newlines (matches doEscapeCharEncode in lteSmsNewMsg.htm)
        message = message.replace("\n", "").replace("\r", "")

        # ACT_SET=2, OID=LTE_SMS_SENDNEWMSG, 3 attributes:
        #   index: 1=send immediately, 2=save to drafts
        #   to: recipient number
        #   textContent: message body (max 765 GSM-7 chars / 335 Unicode chars across 5 concatenated SMS)
        r = self._cgi_gdpr(f"2\r\n[LTE_SMS_SENDNEWMSG#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\nindex=1\r\nto={phone}\r\ntextContent={message}\r\n")
        m = re.search(r"\[error](\d+)", r)
        if m and m.group(1) != "0":
            raise RuntimeError(f"Router returned error code {m.group(1)}")

        # Poll sendResult until the modem confirms (mirrors smsSendResult() in lteSmsNewMsg.htm)
        # 1=success, 2=modem busy, 3=in progress, other=failure
        for _ in range(10):
            time.sleep(0.5)
            r = self._cgi_gdpr("1\r\n[LTE_SMS_SENDNEWMSG#0,0,0,0,0,0#0,0,0,0,0,0]0,1\r\nsendResult\r\n")
            m = re.search(r"sendResult=(\d+)", r)
            if not m:
                continue
            result = int(m.group(1))
            if result == 1:
                return
            if result == 2:
                raise RuntimeError("SMS send failed: modem busy")
            if result != 3:
                raise RuntimeError(f"SMS send failed: sendResult={result}")
        raise RuntimeError("SMS send timed out")

    def logout(self) -> None:
        self._cgi_gdpr("8\r\n[/cgi/clearBusy#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n")
        self._cgi_gdpr("8\r\n[/cgi/logout#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n")

    def get_sms(self, unread_only: bool = False) -> list[dict]:
        """Return inbox messages as a list of dicts with keys: index, from, content, received, unread, stack."""
        # SET pageNumber=1 triggers the router to sync new messages from the modem.
        # The router pages results in groups of 8 (amountPerPage from lteSmsReadMsg.htm);
        # this fetches page 1 only — sufficient for most use cases.
        # Always use RECVMSGBOX/RECVMSGENTRY — stacks from UNREADMSGENTRY are page-relative
        # and cannot be used with mark_read (which requires absolute RECVMSGENTRY stacks).
        self._cgi_gdpr("2\r\n[LTE_SMS_RECVMSGBOX#0,0,0,0,0,0#0,0,0,0,0,0]0,1\r\npageNumber=1\r\n")
        r = self._cgi_gdpr("6\r\n[LTE_SMS_RECVMSGENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,5\r\nindex\r\nfrom\r\ncontent\r\nreceivedTime\r\nunread\r\n")

        messages = []
        for stack, block in re.findall(r"\[(\d+,0,0,0,0,0)]\d+\n(.*?)(?=\[\d|$)", r, re.DOTALL):
            fields = dict(re.findall(r"^(\w+)=(.*)$", block, re.MULTILINE))
            if not fields.get("index") or fields["index"] == "0":
                continue
            is_unread = fields.get("unread", "0") == "1"
            if unread_only and not is_unread:
                continue
            messages.append({
                "index":    fields["index"],
                "from":     fields.get("from", ""),
                "content":  fields.get("content", ""),
                "received": fields.get("receivedTime", ""),
                "unread":   is_unread,
                "stack":    stack,
            })
            if unread_only:
                self.mark_read(stack)
        return messages

    def mark_read(self, stack: str) -> None:
        """Mark a message as read using its RECVMSGENTRY stack address."""
        self._cgi_gdpr(f"2\r\n[LTE_SMS_RECVMSGENTRY#{stack}#0,0,0,0,0,0]0,1\r\nunread=0\r\n")


def main() -> None:
    load_dotenv()
    ip = os.getenv("TL_MR6400_IP")
    pw = os.getenv("TL_MR6400_PASSWORD")
    if not ip or not pw:
        raise SystemExit("Set TL_MR6400_IP and TL_MR6400_PASSWORD in .env")

    ap = argparse.ArgumentParser(description="TP-Link TL-MR6400 SMS tool")
    sub = ap.add_subparsers(dest="cmd", required=True)

    send_p = sub.add_parser("send", help="Send an SMS")
    send_p.add_argument("phone",   help="Recipient number, e.g. +4917612345678")
    send_p.add_argument("message", help="SMS text")

    sub.add_parser("inbox",  help="List all inbox messages")
    sub.add_parser("unread", help="List unread inbox messages only")

    args   = ap.parse_args()
    client = TLMR6400(ip=ip)
    client.login(pw)

    if args.cmd == "send":
        print(f"Sending to {args.phone}: {args.message!r}")
        client.send_sms(args.phone, args.message)
        print("SMS sent successfully.")
    elif args.cmd in ("inbox", "unread"):
        messages = client.get_sms(unread_only=args.cmd == "unread")
        if not messages:
            print("No messages.")
        else:
            for msg in messages:
                status = "UNREAD" if msg["unread"] else "read"
                print(f"[{status}] {msg['received']}  From: {msg['from']}\n  {msg['content']}\n")

    client.logout()


if __name__ == "__main__":
    main()
