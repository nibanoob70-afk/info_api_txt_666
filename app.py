# Free Fire Player Info API - Flask/Vercel compatible
import asyncio
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import httpx
from flask import Flask, jsonify, request
from flask_cors import CORS
from Crypto.Cipher import AES
from google.protobuf import json_format

try:
    import FreeFire_pb2
    import main_pb2
    import AccountPersonalShow_pb2
except ImportError as exc:
    raise RuntimeError(f"Protobuf module import failed: {exc}") from exc

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("freefire-api")

RELEASEVERSION = os.getenv("FF_RELEASE_VERSION", "OB55")
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 14; CPH2095 Build/RKQ1.211119.001)"
MAIN_KEY = b"Yg&tc%DEuh6%Zc^8"
MAIN_IV = b"6oyZDr22E3ychjM%"
JWT_API_BASE = os.getenv("JWT_API_BASE", "https://jwt-wxun.vercel.app/token")

# Set these six values in Vercel -> Project -> Settings -> Environment Variables.
ACCOUNT_CREDENTIALS = {
    "BD": {"uid": "8460435296", "password": "F78C0EBE728F598C6857E752D81390E676B143DA98338C7BE896726E921734C1"},
    "IND": {"uid": os.getenv("IND_UID", ""), "password": os.getenv("IND_PASSWORD", "")},
    "BR": {"uid": os.getenv("BR_UID", ""), "password": os.getenv("BR_PASSWORD", "")},
}

REGION_CONFIG = {
    "BD": {"server_url": "https://clientbp.ppmainecoonghj.com", "release_version": RELEASEVERSION},
    "IND": {"server_url": "https://client.ind.freefiremobile.com", "release_version": RELEASEVERSION},
    "BR": {"server_url": "https://client.us.freefiremobile.com", "release_version": RELEASEVERSION},
}
LOGIN_URLS = {
    "BD": "https://loginbp.ppmainecoonghj.com",
    "IND": "https://loginbp.ppmainecoonghj.com",
    "BR": "https://loginbp.ppmainecoonghj.com",
}
REGION_PRIORITY = ["BD", "IND", "BR"]

app = Flask(__name__)
CORS(app)
_token_cache = {}
_last_region_errors = {}


def credentials_ready(region):
    cred = ACCOUNT_CREDENTIALS.get(region, {})
    return bool(cred.get("uid") and cred.get("password"))


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    block_size = AES.block_size
    padding_length = block_size - (len(plaintext) % block_size)
    padded = plaintext + bytes([padding_length]) * padding_length
    return AES.new(key, AES.MODE_CBC, iv).encrypt(padded)


def json_to_proto(json_data: str, proto_message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()


async def get_jwt_token_from_api(region: str):
    cred = ACCOUNT_CREDENTIALS.get(region)
    if not cred or not credentials_ready(region):
        _last_region_errors[region] = "Missing account credentials in environment variables"
        return None

    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
            response = await client.get(
                JWT_API_BASE,
                params={"uid": cred["uid"], "password": cred["password"]},
                headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
            )
        if response.status_code != 200:
            _last_region_errors[region] = f"JWT service returned HTTP {response.status_code}"
            logger.warning("JWT service failed for %s: HTTP %s", region, response.status_code)
            return None
        try:
            data = response.json()
        except ValueError:
            _last_region_errors[region] = "JWT service returned invalid JSON"
            return None

        token = data.get("token")
        if not token:
            _last_region_errors[region] = "JWT response did not contain token"
            return None

        api_region = str(data.get("region") or region).upper()
        if api_region not in REGION_CONFIG:
            api_region = region
        server_url = data.get("server_url") or data.get("serverUrl") or REGION_CONFIG[api_region]["server_url"]
        _last_region_errors.pop(region, None)
        return {
            "token": str(token) if str(token).startswith("Bearer ") else f"Bearer {token}",
            "region": api_region,
            "server_url": server_url.rstrip("/"),
            "expires_at": time.time() + 6 * 60 * 60,
        }
    except httpx.TimeoutException:
        _last_region_errors[region] = "JWT service timed out"
        return None
    except Exception as exc:
        _last_region_errors[region] = f"JWT request error: {type(exc).__name__}"
        logger.exception("JWT API exception for %s", region)
        return None


async def get_access_token(region: str):
    cred = ACCOUNT_CREDENTIALS.get(region, {})
    if not credentials_ready(region):
        _last_region_errors[region] = "Missing account credentials in environment variables"
        return None, None

    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    form_data = {
        "uid": cred["uid"],
        "password": cred["password"],
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067",
    }
    headers = {"User-Agent": USERAGENT, "Content-Type": "application/x-www-form-urlencoded"}

    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(url, data=form_data, headers=headers)
            if response.status_code == 200:
                data = response.json()
                return data.get("access_token"), data.get("open_id")
            _last_region_errors[region] = f"Guest login returned HTTP {response.status_code}"
        except Exception as exc:
            _last_region_errors[region] = f"Guest login error: {type(exc).__name__}"
            logger.warning("Guest login attempt %s failed for %s", attempt + 1, region)
        if attempt == 0:
            await asyncio.sleep(1)
    return None, None


async def generate_token_backup(region: str):
    try:
        token_val, open_id = await get_access_token(region)
        if not token_val or not open_id:
            return None

        body = json.dumps({
            "open_id": open_id,
            "open_id_type": "4",
            "login_token": token_val,
            "orign_platform_type": "4",
        })
        proto_bytes = json_to_proto(body, FreeFire_pb2.LoginReq())
        payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
        config = REGION_CONFIG[region]
        url = f"{LOGIN_URLS[region]}/MajorLogin"
        headers = {
            "User-Agent": USERAGENT,
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": config["release_version"],
        }
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(url, content=payload, headers=headers)
        if response.status_code != 200:
            _last_region_errors[region] = f"Game login returned HTTP {response.status_code}"
            return None

        login_res = FreeFire_pb2.LoginRes()
        login_res.ParseFromString(response.content)
        msg = json_format.MessageToDict(login_res, preserving_proto_field_name=False)
        token = msg.get("token")
        server_url = msg.get("serverUrl")
        actual_region = str(msg.get("lockRegion") or region).upper()
        if not token or not server_url:
            _last_region_errors[region] = "Game login response is missing token/server URL"
            return None
        if actual_region not in REGION_CONFIG:
            actual_region = region
        _last_region_errors.pop(region, None)
        return {
            "token": f"Bearer {token}",
            "region": actual_region,
            "server_url": server_url.rstrip("/"),
            "expires_at": time.time() + 6 * 60 * 60,
        }
    except Exception as exc:
        _last_region_errors[region] = f"Backup token error: {type(exc).__name__}"
        logger.exception("Backup token generation failed for %s", region)
        return None


async def get_token(region: str):
    cached = _token_cache.get(region)
    if cached and cached.get("expires_at", 0) > time.time() + 60:
        return cached
    token_info = await get_jwt_token_from_api(region)
    if not token_info:
        token_info = await generate_token_backup(region)
    if token_info:
        _token_cache[region] = token_info
    return token_info


async def get_account_information(uid: int, region: str):
    try:
        token_info = await get_token(region)
        if not token_info:
            return None
        actual_region = token_info.get("region", region)
        if actual_region not in REGION_CONFIG:
            actual_region = region
        proto_payload = json_to_proto(
            json.dumps({"a": uid, "b": 7}), main_pb2.GetPlayerPersonalShow()
        )
        encrypted_payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_payload)
        headers = {
            "User-Agent": USERAGENT,
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Authorization": token_info["token"],
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": REGION_CONFIG[actual_region]["release_version"],
        }
        async with httpx.AsyncClient(timeout=18.0) as client:
            response = await client.post(
                token_info["server_url"] + "/GetPlayerPersonalShow",
                content=encrypted_payload,
                headers=headers,
            )
        if response.status_code != 200:
            _last_region_errors[region] = f"Player-info service returned HTTP {response.status_code}"
            return None
        account_info = AccountPersonalShow_pb2.AccountPersonalShowInfo()
        account_info.ParseFromString(response.content)
        result = json_format.MessageToDict(account_info, preserving_proto_field_name=False)
        result["ban_status"] = "❓ UNKNOWN"
        result["region"] = actual_region
        _last_region_errors.pop(region, None)
        return result
    except httpx.TimeoutException:
        _last_region_errors[region] = "Player-info request timed out"
        return None
    except Exception as exc:
        _last_region_errors[region] = f"Player-info error: {type(exc).__name__}"
        logger.exception("Player info request failed for %s", region)
        return None


def get_item_name(item_id):
    if not item_id or str(item_id) == "0":
        return "N/A"
    try:
        import requests
        response = requests.get(f"https://api.danger.workers.dev/item/{item_id}", timeout=3)
        if response.status_code == 200:
            return response.json().get("name", str(item_id))
    except Exception:
        pass
    return str(item_id)


def get_rank_name(points):
    try:
        points = int(points)
    except (TypeError, ValueError):
        return "N/A"
    if points < 100: return "Bronze"
    if points < 300: return "Silver"
    if points < 600: return "Gold"
    if points < 900: return "Platinum"
    if points < 1200: return "Diamond"
    if points < 1500: return "Heroic"
    if points < 2000: return "Master"
    return "Grandmaster"


def ts_to_bst(timestamp):
    try:
        bst = timezone(timedelta(hours=6))
        dt = datetime.fromtimestamp(int(timestamp), tz=timezone.utc).astimezone(bst)
        return dt.strftime("%d %b %Y at %I:%M:%S %p") + " (BST)"
    except (TypeError, ValueError, OSError, OverflowError):
        return "N/A"


async def try_all_regions(uid: int):
    tasks = [asyncio.create_task(get_account_information(uid, region)) for region in REGION_PRIORITY]
    try:
        done, pending = await asyncio.wait(tasks, timeout=35, return_when=asyncio.FIRST_COMPLETED)
        # Continue collecting completed tasks until one returns player data or all finish.
        while done:
            for task in done:
                try:
                    data = task.result()
                    if data:
                        for pending_task in pending:
                            pending_task.cancel()
                        await asyncio.gather(*pending, return_exceptions=True)
                        return data
                except Exception:
                    pass
            if not pending:
                break
            done, pending = await asyncio.wait(pending, timeout=10, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        return None
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()


@app.get("/")
def home():
    return jsonify({
        "status": "running",
        "version": RELEASEVERSION,
        "endpoint": "/info?uid=UID",
        "health": "/health",
        "diagnostics": "/status",
        "priority": "BD -> IND -> BR",
    })


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "Free Fire Info API"}), 200


@app.get("/status")
def status():
    now = time.time()
    tokens = {
        region: {
            "has_token": True,
            "expires_in_seconds": max(0, int(info.get("expires_at", 0) - now)),
        }
        for region, info in _token_cache.items()
    }
    return jsonify({
        "status": "running",
        "credentials_configured": {region: credentials_ready(region) for region in REGION_PRIORITY},
        "token_cache": tokens,
        "region_errors": dict(_last_region_errors),
    })


@app.get("/info")
def get_full_info():
    uid = (request.args.get("uid") or "").strip()
    if not uid:
        return jsonify({"status": "error", "error": "UID required"}), 400
    if not uid.isdigit() or len(uid) > 20:
        return jsonify({"status": "error", "error": "Invalid UID"}), 400

    try:
        account_data = asyncio.run(try_all_regions(int(uid)))
    except Exception as exc:
        logger.exception("Global request error")
        return jsonify({"status": "error", "error": f"Internal request error: {type(exc).__name__}"}), 500

    if not account_data:
        configured = any(credentials_ready(region) for region in REGION_PRIORITY)
        if not configured:
            return jsonify({
                "status": "error",
                "error": "Account credentials are not configured on the hosting platform",
                "region_errors": dict(_last_region_errors),
            }), 503
        return jsonify({
            "status": "error",
            "error": "Player data could not be retrieved",
            "region_errors": dict(_last_region_errors),
        }), 502

    basic = account_data.get("basicInfo", {})
    clan = account_data.get("clanBasicInfo", {})
    social = account_data.get("socialInfo", {})
    pet = account_data.get("petInfo", {})
    captain = account_data.get("captainBasicInfo", {})
    credit = account_data.get("creditScoreInfo", {})
    ranking_points = basic.get("rankingPoints", 0)

    prime_data = basic.get("primeLevel")
    if isinstance(prime_data, dict):
        prime_level = prime_data.get("level", "N/A")
    else:
        prime_level = prime_data if prime_data is not None else "N/A"

    return jsonify({
        "status": "success",
        "server_used": account_data.get("region", "Unknown"),
        "BanStatus": account_data.get("ban_status", "❓ UNKNOWN"),
        "BasicInformation": {
            "PrimeLevel": prime_level,
            "Name": basic.get("nickname", "N/A"),
            "UID": uid,
            "Level": basic.get("level", "N/A"),
            "Exp": basic.get("exp", "N/A"),
            "Region": basic.get("region", "N/A"),
            "Likes": basic.get("liked", "N/A"),
            "HonorScore": credit.get("creditScore", "N/A"),
            "CelebrityStatus": "Yes" if basic.get("showBrRank") else "No",
            "Title": get_item_name(basic.get("title", 0)),
            "Signature": social.get("signature", "N/A"),
        },
        "ActivityInformation": {
            "MostRecentOB": basic.get("releaseVersion", "N/A"),
            "BooyahPass": "Yes" if basic.get("hasElitePass") else "No",
            "CurrentBpBadges": basic.get("badgeCnt", "N/A"),
            "BRRank": get_rank_name(ranking_points),
            "BRPoints": ranking_points,
            "ShowBRRank": bool(basic.get("showBrRank", False)),
            "ShowCSRank": bool(basic.get("showCsRank", False)),
            "CreatedAt": ts_to_bst(basic.get("createAt", 0)),
            "LastLogin": ts_to_bst(basic.get("lastLoginAt", 0)),
        },
        "GuildInformation": {
            "GuildName": clan.get("clanName", "No Guild"),
            "GuildID": clan.get("clanId", "N/A"),
            "GuildLevel": clan.get("clanLevel", "N/A"),
            "LiveMembers": clan.get("memberNum", "N/A"),
            "MaxMembers": clan.get("capacity", "N/A"),
        },
        "PetDetails": {
            "Equipped": "Yes" if pet.get("isSelected") else "No",
            "PetNick": pet.get("name", "N/A"),
            "PetType": get_item_name(pet.get("id", 0)),
            "PetSkill": get_item_name(pet.get("selectedSkillId", 0)),
            "PetSkin": get_item_name(pet.get("skinId", 0)),
            "PetExp": pet.get("exp", "N/A"),
            "PetLevel": pet.get("level", "N/A"),
        },
        "LeaderInformation": {
            "Name": captain.get("nickname", "N/A"),
            "UID": captain.get("accountId", "N/A"),
            "Level": captain.get("level", "N/A"),
            "Region": captain.get("region", "N/A"),
            "BooyahPass": "Yes" if captain.get("hasElitePass") else "No",
            "CreatedAt": ts_to_bst(captain.get("createAt", 0)),
            "LastLogin": ts_to_bst(captain.get("lastLoginAt", 0)),
            "MostRecentOB": captain.get("releaseVersion", "N/A"),
            "Title": get_item_name(captain.get("title", 0)),
            "BpBadges": captain.get("badgeCnt", "N/A"),
            "BRRank": get_rank_name(captain.get("rankingPoints", 0)),
            "BRPoints": captain.get("rankingPoints", 0),
        },
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5004")), debug=False)