import asyncio
import base64
import json
import struct
import time
from datetime import datetime

import httpx
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from flask import Flask, jsonify, request
from flask_cors import CORS
from google.protobuf import json_format

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import AccountPersonalShow_pb2
import main_pb2
import thunderFF_pb2


app = Flask(__name__)
app.json.sort_keys = False
CORS(app)

USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 14; CPH2095 Build/RKQ1.211119.001)"
MAIN_KEY = b'Yg&tc%DEuh6%Zc^8'
MAIN_IV = b'6oyZDr22E3ychjM%'

JWT_TIMEOUT = 20.0
JWT_RETRY = 2
JWT_CV = "1.132.3"
JWT_RLS = "OB55"
JWT_TTL = 7 * 3600

OAUTH_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"
INSPECT_URL = "https://100067.connect.garena.com/oauth/token/inspect"
CLIENT_ID = "100067"
CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"

ACCOUNTS = {
    "IND": {
        "uid": "5442675493",
        "password": "dace607b859beefcbf63b21894842dd10ff8362ca935268ceb7d63c995543dae",
    },
    "BR": {
        "uid": "5969022021",
        "password": "76AAD2830110AFA64C216B00F766D9C24DAC508125D020A7D149E6F0ABCBC62F",
    },
    "BD": {
        "uid": "4678032558",
        "password": "64c1ba97f31d2bb5fc591bd0657a1a4b",
    },
}

LOGIN_HOSTS = {
    "IND": "https://loginbp.ggblueshark.com/MajorLogin",
    "BD": "https://loginbp.ggblueshark.com/MajorLogin",
    "BR": "https://loginbp.ggpolarbear.com/MajorLogin",
}

REGION_TO_POOL = {
    "IND": "IND",
    "BR": "BR", "NA": "BR", "SAC": "BR", "US": "BR",
}

SEARCH_ORDER = ["IND", "BD", "BR"]

DEV_CREDIT = "@viswajeethu"

TOKEN_CACHE = {}


def resolve_pool(region):
    if not region:
        return "BD"
    return REGION_TO_POOL.get(region.upper().strip(), "BD")


def aes_encrypt(data):
    return AES.new(MAIN_KEY, AES.MODE_CBC, MAIN_IV).encrypt(pad(data, 16))


async def json_to_proto(json_data, proto_message):
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()


def _rd_var(b, pos, end):
    v, sh = 0, 0
    while pos < end:
        x = b[pos]
        pos += 1
        v |= (x & 0x7F) << sh
        if not x & 0x80:
            break
        sh += 7
    return v, pos


def _walk(b, pos=0, end=None):
    if end is None:
        end = len(b)
    out = {}
    while pos < end:
        tag, pos = _rd_var(b, pos, end)
        f, w = tag >> 3, tag & 7
        if w == 0:
            v, pos = _rd_var(b, pos, end)
            out.setdefault(f, []).append(v)
        elif w == 2:
            ln, pos = _rd_var(b, pos, end)
            if pos + ln > end:
                break
            raw = b[pos:pos + ln]
            pos += ln
            ok = False
            try:
                s = raw.decode("utf-8")
                if all(c.isprintable() or c in "\n\r\t" for c in s):
                    out.setdefault(f, []).append(s)
                    ok = True
            except Exception:
                pass
            if not ok:
                sub = None
                try:
                    sub = _walk(raw, 0, len(raw)) or None
                except Exception:
                    pass
                out.setdefault(f, []).append(sub if sub else raw.hex())
        elif w == 5:
            out.setdefault(f, []).append(struct.unpack_from("<f", b, pos)[0])
            pos += 4
        elif w == 1:
            out.setdefault(f, []).append(struct.unpack_from("<d", b, pos)[0])
            pos += 8
        else:
            break
    return out


def _find_proto_root(raw):
    for i in range(len(raw) - 10):
        if raw[i] in (0x08, 0x12):
            try:
                t = _walk(raw, i, len(raw))
                if 1 in t and isinstance(t[1][0], int) and t[1][0] > 100000000:
                    return i, t
                if 2 in t and isinstance(t[2][0], str) and t[2][0].isalpha():
                    return i, t
            except Exception:
                continue
    return 0, {}


def _search_jwt_in_vals(vals):
    if not isinstance(vals, list):
        vals = [vals]
    for v in vals:
        if isinstance(v, str):
            if v.startswith("eyJ") and v.count(".") == 2 and len(v) > 100:
                return v
            if len(v) > 20 and all(c in "0123456789abcdefABCDEF" for c in v):
                try:
                    dec = bytes.fromhex(v)
                    idx = dec.find(b"eyJ")
                    if idx != -1:
                        allowed = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_."
                        end = idx
                        while end < len(dec) and dec[end] in allowed:
                            end += 1
                        cand = dec[idx:end].decode("ascii", errors="ignore")
                        if cand.count(".") == 2 and len(cand) > 100:
                            return cand
                except Exception:
                    pass
        elif isinstance(v, dict):
            f = _extract_jwt_from_tree(v)
            if f:
                return f
        elif isinstance(v, list):
            f = _search_jwt_in_vals(v)
            if f:
                return f
    return None


def _extract_jwt_from_tree(tree):
    if not isinstance(tree, dict):
        return None
    if tree.get(8):
        f = _search_jwt_in_vals(tree[8])
        if f:
            return f
    for _, vals in tree.items():
        f = _search_jwt_in_vals(vals)
        if f:
            return f
    return None


def extract_jwt(raw):
    if not raw:
        return None
    _, tree = _find_proto_root(raw)
    j = _extract_jwt_from_tree(tree)
    if j:
        return j
    start = raw.find(b"eyJ")
    while start != -1:
        allowed = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_."
        end = start
        while end < len(raw) and raw[end] in allowed:
            end += 1
        cand = raw[start:end].decode("utf-8", errors="ignore")
        if cand.count(".") == 2 and len(cand) > 100:
            return cand
        start = raw.find(b"eyJ", start + 1)
    return None


def _deep_strings(node, depth=0, max_depth=6, out=None):
    if out is None:
        out = []
    if depth > max_depth:
        return out
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            _deep_strings(v, depth + 1, max_depth, out)
    elif isinstance(node, list):
        for v in node:
            _deep_strings(v, depth + 1, max_depth, out)
    return out


def parse_majorlogin(raw):
    result = {"jwt": None, "server_url": None, "lock_region": None}
    if not raw:
        return result
    result["jwt"] = extract_jwt(raw)
    _, tree = _find_proto_root(raw)
    for s in _deep_strings(tree):
        if not result["server_url"] and s.startswith("https://") and "client" in s.lower():
            result["server_url"] = s.rstrip("/")
        elif not result["lock_region"] and 2 <= len(s) <= 4 and s.isalpha():
            result["lock_region"] = s.upper()
    return result


def decode_jwt_payload(jwt):
    try:
        parts = jwt.split(".")
        if len(parts) != 3:
            return {}
        p = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception:
        return {}


async def _oauth(uid, password):
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/5.5.2P3(SM-A515F;Android 12;en-US;IND;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": CLIENT_SECRET,
        "client_id": CLIENT_ID,
    }
    last = None
    for i in range(JWT_RETRY + 1):
        try:
            async with httpx.AsyncClient(timeout=JWT_TIMEOUT, verify=False) as c:
                r = await c.post(OAUTH_URL, headers=headers, data=data)
                if r.status_code == 200:
                    j = r.json()
                    return j.get("open_id"), j.get("access_token"), j.get("platform", 4), None
                if r.status_code == 429:
                    return None, None, None, "Rate limited (429)"
                last = r.text
        except Exception as e:
            last = str(e)
        if i < JWT_RETRY:
            await asyncio.sleep(1)
    return None, None, None, last


async def _inspect(token):
    headers = {"User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)"}
    async with httpx.AsyncClient(timeout=JWT_TIMEOUT, verify=False) as c:
        r = await c.get(f"{INSPECT_URL}?token={token}", headers=headers)
        return r.json()


def build_login_payload(open_id, access_token, platform, cv):
    P = thunderFF_pb2.MajorLoginReq()
    P.event_time = str(datetime.now())[:-7]
    P.game_name = "free fire"
    P.platform_id = 2
    P.client_version = cv
    P.client_version_code = "2024010012"
    P.system_software = "Android OS 11 / API-30"
    P.system_hardware = "Handheld"
    P.device_type = "Handheld"
    P.telecom_operator = "Verizon"
    P.network_operator_a = "Verizon"
    P.network_type = "WIFI"
    P.network_type_a = "WIFI"
    P.screen_width = 1080
    P.screen_height = 2400
    P.screen_dpi = "440"
    P.processor_details = "ARMv8"
    P.cpu_type = 2
    P.cpu_architecture = "64"
    P.memory = 6144
    P.gpu_renderer = "Adreno (TM) 650"
    P.gpu_version = "OpenGL ES 3.2"
    P.graphics_api = "OpenGLES3"
    P.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    P.client_ip = ""
    P.language = "en"
    P.open_id = open_id
    P.open_id_type = str(platform)
    P.login_open_id_type = int(platform)
    P.access_token = access_token
    P.login_by = 3
    P.platform_sdk_id = 2
    P.origin_platform_type = str(platform)
    P.primary_platform_type = str(platform)
    P.external_storage_total = 128512
    P.external_storage_available = 45000
    P.internal_storage_total = 110731
    P.internal_storage_available = 25000
    P.game_disk_storage_total = 26628
    P.game_disk_storage_available = 20000
    P.external_sdcard_total_storage = 119234
    P.external_sdcard_avail_storage = 40000
    P.library_path = "/data/app/~~random/base.apk"
    P.library_token = "hash|base.apk"
    P.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    P.supported_astc_bitset = 16383
    P.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    P.loading_time = 12000
    P.release_channel = "android"
    P.channel_type = 3
    P.reg_avatar = 1
    P.if_push = 1
    P.is_vpn = 0
    P.android_engine_init_flag = 110009
    return aes_encrypt(P.SerializeToString())


async def majorlogin(payload, rls, login_url):
    headers = {
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-Ga-Sv": str(int(time.time())),
        "Authorization": "Bearer",
        "X-Ga": "v1 1",
        "Releaseversion": rls,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
    }
    last = None
    for i in range(JWT_RETRY + 1):
        try:
            async with httpx.AsyncClient(timeout=JWT_TIMEOUT, verify=False) as c:
                r = await c.post(login_url, headers=headers, content=payload)
                if r.status_code == 200:
                    return r
                last = f"HTTP {r.status_code}"
        except Exception as e:
            last = str(e)
        if i < JWT_RETRY:
            await asyncio.sleep(1)
    raise Exception(f"MajorLogin failed: {last}")


async def generate_jwt(pool):
    cred = ACCOUNTS.get(pool)
    if not cred:
        return None

    oid, tok, plat, err = await _oauth(cred["uid"], cred["password"])
    if err:
        print(f"OAuth [{pool}]: {err}")
        return None
    if not oid or not tok:
        print(f"OAuth [{pool}]: no open_id/access_token")
        return None

    try:
        inf = await _inspect(tok)
    except Exception as e:
        print(f"Inspect [{pool}]: {e}")
        return None
    if "open_id" not in inf:
        print(f"Inspect [{pool}]: {inf}")
        return None

    oid = inf["open_id"]
    plat = str(inf.get("platform", plat or 4))

    login_url = LOGIN_HOSTS.get(pool, LOGIN_HOSTS["BD"])
    try:
        payload = build_login_payload(oid, tok, plat, JWT_CV)
        resp = await majorlogin(payload, JWT_RLS, login_url)
    except Exception as e:
        print(f"MajorLogin [{pool}]: {e}")
        return None

    parsed = parse_majorlogin(resp.content)
    jwt = parsed.get("jwt")
    if not jwt:
        print(f"No JWT [{pool}]")
        return None

    server_url = parsed.get("server_url")
    if not server_url:
        print(f"No server_url [{pool}]")
        return None

    real_region = None
    payload_jwt = decode_jwt_payload(jwt)
    for k in ("lock_region", "lockRegion", "region"):
        v = payload_jwt.get(k)
        if isinstance(v, str) and v:
            real_region = v.upper()
            break
    if not real_region:
        real_region = parsed.get("lock_region") or pool

    print(f"JWT ready [pool={pool}] -> token_region={real_region} @ {server_url}")

    return {
        "token": f"Bearer {jwt}",
        "pool": pool,
        "token_region": real_region,
        "server_url": server_url,
        "expires_at": time.time() + JWT_TTL,
    }


async def get_token(pool, force=False):
    cached = TOKEN_CACHE.get(pool)
    if not force and cached and cached.get("expires_at", 0) > time.time() + 60:
        return cached

    info = await generate_jwt(pool)
    if info:
        TOKEN_CACHE[pool] = info
    return info


async def get_player_info(uid, pool, _retry=0):
    try:
        token_info = await get_token(pool, force=(_retry > 0))
        if not token_info:
            return None

        server_url = token_info["server_url"]
        token = token_info["token"]

        payload = await json_to_proto(
            json.dumps({"a": uid, "b": "7"}),
            main_pb2.GetPlayerPersonalShow(),
        )
        data_enc = aes_encrypt(payload)

        headers = {
            "User-Agent": USERAGENT,
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Authorization": token,
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": JWT_RLS,
        }

        url = server_url.rstrip("/") + "/GetPlayerPersonalShow"

        async with httpx.AsyncClient(timeout=20.0, verify=False) as c:
            r = await c.post(url, data=data_enc, headers=headers)

        if r.status_code == 401 and _retry == 0:
            TOKEN_CACHE.pop(pool, None)
            return await get_player_info(uid, pool, _retry=1)

        if r.status_code != 200:
            print(f"GetPlayerPersonalShow [{pool}] {url} -> {r.status_code}")
            return None

        info = AccountPersonalShow_pb2.AccountPersonalShowInfo()
        info.ParseFromString(r.content)
        return json.loads(json_format.MessageToJson(info))
    except Exception as e:
        print(f"get_player_info[{pool}]: {e}")
        return None


def reshape_profile_info(data):
    pi = data.get("profileInfo")
    if not isinstance(pi, dict) or not pi:
        return data

    new_pi = {}

    if "avatarId" in pi:
        new_pi["avatarId"] = pi["avatarId"]

    if "skinColor" in pi:
        new_pi["clothes"] = [pi["skinColor"]]

    if "clothes" in pi:
        new_pi["equipedSkills"] = pi["clothes"]

    for k in ("pvePrimaryWeapon", "endTime", "isMarkedStar"):
        if k in pi:
            new_pi[k] = pi[k]

    data["profileInfo"] = new_pi
    return data


def is_valid_response(data):
    if not isinstance(data, dict):
        return False
    bi = data.get("basicInfo")
    if not isinstance(bi, dict):
        return False
    return bool(bi.get("nickname"))


@app.route("/")
def home():
    return jsonify({
        "status": "running",
        "version": JWT_RLS,
        "endpoint": "/info?uid=UID[&region=REGION]",
        "auto_search_order": SEARCH_ORDER,
        "cache": "in-memory, 7h TTL",
        "dev": DEV_CREDIT,
    })


@app.route("/info")
def info():
    uid = request.args.get("uid")
    region_arg = (request.args.get("region") or "").upper().strip()

    if not uid:
        return jsonify({"error": "UID required"}), 400
    try:
        uid_int = int(uid)
    except ValueError:
        return jsonify({"error": "Invalid UID"}), 400

    if region_arg:
        pool = resolve_pool(region_arg)
        plan = [(pool, region_arg)]
    else:
        plan = [(p, p) for p in SEARCH_ORDER]

    async def run():
        for pool, _ in plan:
            try:
                data = await get_player_info(uid_int, pool)
            except Exception as e:
                print(f"run[{pool}]: {e}")
                data = None
            if data and is_valid_response(data):
                print(f"Found in {pool}")
                return data
            print(f"No valid data in {pool}, trying next...")
        return None

    try:
        data = asyncio.run(run())
    except Exception as e:
        print(f"Global error: {e}")
        data = None

    if not data:
        return jsonify({
            "error": "Player not found",
            "region_requested": region_arg or "auto",
            "searched_pools": [p for p, _ in plan],
        }), 404

    data = reshape_profile_info(data)
    data["Dev"] = DEV_CREDIT
    return jsonify(data)


@app.route("/status")
def status():
    now = time.time()
    return jsonify({
        pool: {
            "token_region": info["token_region"],
            "server_url": info["server_url"],
            "expires_in_hours": round((info["expires_at"] - now) / 3600, 2),
        }
        for pool, info in TOKEN_CACHE.items()
    })


@app.route("/refresh")
def refresh():
    TOKEN_CACHE.clear()

    async def run():
        for p in SEARCH_ORDER:
            await get_token(p, force=True)

    try:
        asyncio.run(run())
        return jsonify({"status": "refreshed", "pools": list(TOKEN_CACHE.keys())})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5004, debug=False)