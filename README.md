# tp-sms

Command-line tool to send and receive SMS via the TP-Link TL-MR6400 web API.

## Requirements

```
pip install requests pycryptodome python-dotenv
```

## Configuration

Create a `.env` file in the same directory:

```
TL_MR6400_IP=192.168.1.1
TL_MR6400_PASSWORD=yourpassword
```

## Usage

```
python tp-sms.py send <phone> <message>   # Send an SMS
python tp-sms.py inbox                    # List all inbox messages
python tp-sms.py unread                   # List unread messages and mark them as read
```

### Examples

```
python tp-sms.py send "+4917612345678" "Hello!"
python tp-sms.py inbox
python tp-sms.py unread
```

## How it works

The router exposes a web API at `http://<ip>/cgi_gdpr`. All requests are encrypted:

- **AES-128-CBC** (random one-time key + IV per session) encrypts the request payload
- **RSA** (router's public key) encrypts the signing header containing the AES key, IV, password hash and sequence number
- A **CSRF token** extracted from the post-login page is sent as `TokenID` on all subsequent requests

The login sequence follows the router's own JS flow (`proxy.js`, `encrypt.js`):

1. `GET /` — prime the session cookie
2. `POST /cgi/getParm` — fetch RSA public key and sequence number
3. `POST /cgi/getBusy` — claim the session
4. `POST /cgi/login` — encrypted credentials
5. `GET /` — extract CSRF token from page JS

### cgi_gdpr call format

Each request body is a plaintext string (AES-encrypted before sending) with the format:

```
<ACT>\r\n
[<OID>#<stack>#<pstack>]<batch_index>,<attr_count>\r\n
<attr1>=<value1>\r\n   ← for SET: key=value pairs
<attr1>\r\n            ← for GS/GL: field names as selector
```

| Field | Description |
|-------|-------------|
| `ACT` | Action: `1`=GET, `2`=SET, `3`=ADD, `4`=DEL, `5`=GL (get list), `6`=GS (get subset), `7`=OP, `8`=CGI |
| `OID` | Object identifier, e.g. `LTE_SMS_RECVMSGENTRY` |
| `stack` | Object's position in the router's internal tree (6 integers). `0,0,0,0,0,0` = root/default. Non-zero targets a specific entry, e.g. `3,0,0,0,0,0` = third entry |
| `pstack` | Parent stack — always `0,0,0,0,0,0` for top-level objects |
| `batch_index` | Position of this OID in a batched request (0-based) |
| `attr_count` | Number of attribute lines that follow — simply count them |

The response uses the same `[stack]pstack\n` format per returned object, with `key=value` lines for each field. Responses always end with `[error]0\n` on success or `[error]<code>\n` on failure.

### SMS retrieval sequence

Setting `pageNumber=1` on `LTE_SMS_RECVMSGBOX` triggers the router to sync new messages from the modem before `LTE_SMS_RECVMSGENTRY` is fetched. This mirrors what the web UI does in `initSmsInboxTable()` in `lteSmsInbox.htm`.

## OID Reference

All OIDs are defined in `/js/oid_str.js` on the router (accessible after login). The full list as extracted from firmware:

### SMS (`LTE_SMS_*`)

Fields are discovered by calling GS (ACT=6) with `attr_count=0` — the router returns all available fields.
Box OIDs respond to GET (ACT=1); entry OIDs respond to GS (ACT=6) after setting `pageNumber=1` on the parent box.
Results are paged in groups of 8 (`amountPerPage` as seen in `lteSmsReadMsg.htm`) — only page 1 is fetched by this script.

| OID | ACT | Fields |
|-----|-----|--------|
| `LTE_SMS` | — | top-level container, no direct fields |
| `LTE_SMS_CONFIG` | GET/SET | `smsReport` (delivery reports on/off), `messageCenter` (on/off), `messageCenterNumber`, `saveSentMsg` (save to outbox on/off) |
| `LTE_SMS_SENDNEWMSG` | SET/GET | `index` (1=send via SIM 1, 2=save to drafts), `to`, `textContent`, `sendTime`, `sendResult` (1=success, 2=busy, 3=in progress) |
| `LTE_SMS_RECVMSGBOX` | GET/SET | `totalNumber`, `pageNumber` — SET `pageNumber=1` to sync from modem |
| `LTE_SMS_RECVMSGENTRY` | GS | `index`, `from`, `content`, `receivedTime`, `unread` — stacks are absolute, usable for SET |
| `LTE_SMS_SENDMSGBOX` | GET/SET | `totalNumber`, `pageNumber` |
| `LTE_SMS_SENDMSGENTRY` | GS | `index`, `to`, `content`, `sendTime` |
| `LTE_SMS_DRAFTMSGBOX` | GET/SET | `totalNumber`, `pageNumber` |
| `LTE_SMS_DRAFTMSGENTRY` | GS | `index`, `to`, `content` |
| `LTE_SMS_UNREADMSGBOX` | GET/SET | `totalNumber`, `pageNumber` |
| `LTE_SMS_UNREADMSGENTRY` | GS | `index`, `from`, `content`, `receivedTime`, `unread` — stacks are page-relative, **not** usable for SET |

**Message length limits** (from `lteSmsNewMsg.htm`):
- GSM-7 charset: 160 chars/SMS, max 5 concatenated = **765 chars**
- Unicode (non-GSM-7): 70 chars/SMS, max 5 concatenated = **335 chars**

### LTE Status (`LTE_NET_STATUS`)

Two instances (SIM 1 and SIM 2), fields:

| Field | Description |
|-------|-------------|
| `sigLevel` | Signal strength (0–5) |
| `connStat` | Connection status (4 = connected) |
| `regStat` | Registration status (1 = registered) |
| `netType` | Network type (3 = LTE) |
| `srvStat` | Service status (2 = in service) |
| `roamStat` | Roaming status |
| `netSelStat` | Network selection status |
| `smsUnreadCount` | Number of unread SMS |
| `smsSendResult` | Last send result (1 = success) |
| `rfInfoRssi` | RSSI (dBm) |
| `rfInfoRsrp` | RSRP (dBm) |
| `rfInfoRsrq` | RSRQ (dB) |
| `rfInfoSnr` | SNR |
| `rfInfoBand` | LTE band |
| `rfInfoChannel` | Channel number |
| `rfInfoRat` | Radio access technology |
| `ussdStatus` | USSD status |
| `rfSwitch` | RF on/off |
| `region` | Region code |

### SIM (`LTE_SIMLOCK`)

Two instances (SIM 1 and SIM 2), fields:

| Field | Description |
|-------|-------------|
| `pinState` | PIN state (2 = unlocked, 3 = locked) |
| `pin` | Current PIN |
| `newPin` | New PIN (for change) |
| `puk` | PUK code |
| `autoUnlockPin` | Auto-unlock PIN on boot |
| `remainPinUnlockTime` | PIN attempts remaining |
| `remainPukUnlockTime` | PUK attempts remaining |
| `simAction` | SIM action (0 = none, 1 = active) |
