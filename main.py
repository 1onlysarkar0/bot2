import requests, os, psutil, sys, jwt, pickle, json, binascii, time, urllib3, base64, datetime, re, socket, threading, ssl, pytz, aiohttp
from protobuf_decoder.protobuf_decoder import Parser
from xC4 import *
from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from Pb2 import DEcwHisPErMsG_pb2, MajoRLoGinrEs_pb2, PorTs_pb2, MajoRLoGinrEq_pb2, sQ_pb2, Team_msg_pb2
from cfonts import render, say
from config_manager import config_manager
from aiohttp import web

import random
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# VariabLes dyli
#------------------------------------------#
online_writer = None
whisper_writer = None
spam_room = False
spammer_uid = None
spam_chat_id = None
spam_uid = None
Spy = False
Chat_Leave = False

# Bot Runtime - shared state for API
bot_runtime = {
    'online_writer': None,
    'whisper_writer': None,
    'key': None,
    'iv': None,
    'region': None,
    'ready': False
}

#------------------------------------------#

####################################


#Clan-info-by-clan-id
def Get_clan_info(clan_id):
    try:
        url = f"https://get-clan-info.vercel.app/get_clan_info?clan_id={clan_id}"
        res = requests.get(url)
        if res.status_code == 200:
            data = res.json()
            msg = f""" 
[11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
▶▶▶▶GUILD DETAILS◀◀◀◀
Achievements: {data['achievements']}\n\n
Balance : {fix_num(data['balance'])}\n\n
Clan Name : {data['clan_name']}\n\n
Expire Time : {fix_num(data['guild_details']['expire_time'])}\n\n
Members Online : {fix_num(data['guild_details']['members_online'])}\n\n
Regional : {data['guild_details']['regional']}\n\n
Reward Time : {fix_num(data['guild_details']['reward_time'])}\n\n
Total Members : {fix_num(data['guild_details']['total_members'])}\n\n
ID : {fix_num(data['id'])}\n\n
Last Active : {fix_num(data['last_active'])}\n\n
Level : {fix_num(data['level'])}\n\n
Rank : {fix_num(data['rank'])}\n\n
Region : {data['region']}\n\n
Score : {fix_num(data['score'])}\n\n
Timestamp1 : {fix_num(data['timestamp1'])}\n\n
Timestamp2 : {fix_num(data['timestamp2'])}\n\n
Welcome Message: {data['welcome_message']}\n\n
XP: {fix_num(data['xp'])}\n\n
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]MADE BY 1onlysarkar
            """
            return msg
        else:
            msg = """
[11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
Failed to get info, please try again later!!

°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]MADE BY 1onlysarkar
            """
            return msg
    except:
        pass


#GET INFO BY PLAYER ID
def get_player_info(player_id):
    url = f"https://like2.vercel.app/player-info?uid={player_id}&server={server2}&key={key2}"
    response = requests.get(url)
    print(response)
    if response.status_code == 200:
        try:
            r = response.json()
            return {
                "Account Booyah Pass": f"{r.get('booyah_pass_level', 'N/A')}",
                "Account Create": f"{r.get('createAt', 'N/A')}",
                "Account Level": f"{r.get('level', 'N/A')}",
                "Account Likes": f" {r.get('likes', 'N/A')}",
                "Name": f"{r.get('nickname', 'N/A')}",
                "UID": f" {r.get('accountId', 'N/A')}",
                "Account Region": f"{r.get('region', 'N/A')}",
            }
        except ValueError as e:
            pass
            return {"error": "Invalid JSON response"}
    else:
        pass
        return {"error": f"Failed to fetch data: {response.status_code}"}


#CHAT WITH AI
def talk_with_ai(question):
    url = f"https://gemini-api-api-v2.vercel.app/prince/api/v1/ask?key=prince&ask={question}"
    res = requests.get(url)
    if res.status_code == 200:
        data = res.json()
        msg = data["message"]["content"]
        return msg
    else:
        return "An error occurred while connecting to the server."


#SPAM REQUESTS
def spam_requests(player_id):
    # This URL now correctly points to the Flask app you provided
    url = f"https://like2.vercel.app/send_requests?uid={player_id}&server={server2}&key={key2}"
    try:
        res = requests.get(url, timeout=20)  # Added a timeout
        if res.status_code == 200:
            data = res.json()
            # Return a more descriptive message based on the API's JSON response
            return f"API Status: Success [{data.get('success_count', 0)}] Failed [{data.get('failed_count', 0)}]"
        else:
            # Return the error status from the API
            return f"API Error: Status {res.status_code}"
    except requests.exceptions.RequestException as e:
        # Handle cases where the API isn't running or is unreachable
        print(f"Could not connect to spam API: {e}")
        return "Failed to connect to spam API."


####################################


# ** NEW INFO FUNCTION using the new API **
def newinfo(uid):
    # Base URL without parameters
    url = "https://like2.vercel.app/player-info"
    # Parameters dictionary - this is the robust way to do it
    params = {
        'uid': uid,
        'server': server2,  # Hardcoded to bd as requested
        'key': key2
    }
    try:
        # Pass the parameters to requests.get()
        response = requests.get(url, params=params, timeout=10)

        # Check if the request was successful
        if response.status_code == 200:
            data = response.json()
            # Check if the expected data structure is in the response
            if "basicInfo" in data:
                return {"status": "ok", "data": data}
            else:
                # The API returned 200, but the data is not what we expect (e.g., error message in JSON)
                return {
                    "status": "error",
                    "message": data.get("error",
                                        "Invalid ID or data not found.")
                }
        else:
            # The API returned an error status code (e.g., 404, 500)
            try:
                # Try to get a specific error message from the API's response
                error_msg = response.json().get(
                    'error', f"API returned status {response.status_code}")
                return {"status": "error", "message": error_msg}
            except ValueError:
                # If the error response is not JSON
                return {
                    "status": "error",
                    "message": f"API returned status {response.status_code}"
                }

    except requests.exceptions.RequestException as e:
        # Handle network errors (e.g., timeout, no connection)
        return {"status": "error", "message": f"Network error: {str(e)}"}
    except ValueError:
        # Handle cases where the response is not valid JSON
        return {
            "status": "error",
            "message": "Invalid JSON response from API."
        }


#ADDING-100-LIKES-IN-24H
def send_likes(uid):
    try:
        likes_api_response = requests.get(
            f"https://yourlikeapi/like?uid={uid}&server_name={server2}&x-vercel-set-bypass-cookie=true&x-vercel-protection-bypass={BYPASS_TOKEN}",
            timeout=15)

        if likes_api_response.status_code != 200:
            return f"""
[C][B][FF0000]━━━━━
[FFFFFF]Like API Error!
Status Code: {likes_api_response.status_code}
Please check if the uid is correct.
━━━━━
"""

        api_json_response = likes_api_response.json()

        player_name = api_json_response.get('PlayerNickname', 'Unknown')
        likes_before = api_json_response.get('LikesbeforeCommand', 0)
        likes_after = api_json_response.get('LikesafterCommand', 0)
        likes_added = api_json_response.get('LikesGivenByAPI', 0)
        status = api_json_response.get('status', 0)

        if status == 1 and likes_added > 0:
            # ✅ Success
            return f"""
[C][B][11EAFD]‎━━━━━━━━━━━━
[FFFFFF]Likes Status:

[00FF00]Likes Sent Successfully!

[FFFFFF]Player Name : [00FF00]{player_name}  
[FFFFFF]Likes Added : [00FF00]{likes_added}  
[FFFFFF]Likes Before : [00FF00]{likes_before}  
[FFFFFF]Likes After : [00FF00]{likes_after}  
[C][B][11EAFD]‎━━━━━━━━━━━━
[C][B][FFB300]Instagram: [FFFFFF]@1onlysarkar [00FF00]!!
"""
        elif status == 2 or likes_before == likes_after:
            # 🚫 Already claimed / Maxed
            return f"""
[C][B][FF0000]━━━━━━━━━━━━

[FFFFFF]No Likes Sent!

[FF0000]You have already taken likes with this UID.
Try again after 24 hours.

[FFFFFF]Player Name : [FF0000]{player_name}  
[FFFFFF]Likes Before : [FF0000]{likes_before}  
[FFFFFF]Likes After : [FF0000]{likes_after}  
[C][B][FF0000]━━━━━━━━━━━━
"""
        else:
            # ❓ Unexpected case
            return f"""
[C][B][FF0000]━━━━━━━━━━━━
[FFFFFF]Unexpected Response!
Something went wrong.

Please try again or contact support.
━━━━━━━━━━━━
"""

    except requests.exceptions.RequestException:
        return """
[C][B][FF0000]━━━━━
[FFFFFF]Like API Connection Failed!
Is the API server (app.py) running?
━━━━━
"""
    except Exception as e:
        return f"""
[C][B][FF0000]━━━━━
[FFFFFF]An unexpected error occurred:
[FF0000]{str(e)}
━━━━━
"""


####################################
#CHECK ACCOUNT IS BANNED

Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB51"
}


# ---- Random Colores ----
def get_random_color():
    colors = [
        "[FF0000]", "[00FF00]", "[0000FF]", "[FFFF00]", "[FF00FF]", "[00FFFF]",
        "[FFFFFF]", "[FFA500]", "[A52A2A]", "[800080]", "[000000]", "[808080]",
        "[C0C0C0]", "[FFC0CB]", "[FFD700]", "[ADD8E6]", "[90EE90]", "[D2691E]",
        "[DC143C]", "[00CED1]", "[9400D3]", "[F08080]", "[20B2AA]", "[FF1493]",
        "[7CFC00]", "[B22222]", "[FF4500]", "[DAA520]", "[00BFFF]", "[00FF7F]",
        "[4682B4]", "[6495ED]", "[5F9EA0]", "[DDA0DD]", "[E6E6FA]", "[B0C4DE]",
        "[556B2F]", "[8FBC8F]", "[2E8B57]", "[3CB371]", "[6B8E23]", "[808000]",
        "[B8860B]", "[CD5C5C]", "[8B0000]", "[FF6347]", "[FF8C00]", "[BDB76B]",
        "[9932CC]", "[8A2BE2]", "[4B0082]", "[6A5ACD]", "[7B68EE]", "[4169E1]",
        "[1E90FF]", "[191970]", "[00008B]", "[000080]", "[008080]", "[008B8B]",
        "[B0E0E6]", "[AFEEEE]", "[E0FFFF]", "[F5F5DC]", "[FAEBD7]"
    ]
    return random.choice(colors)


async def encrypted_proto(encoded_hex):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload


async def GeNeRaTeAccEss(uid, password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": (await Ua()),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret":
        "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=Hr, data=data) as response:
            if response.status != 200:
                print(f"Failed to get access token: {response.status}")
                return (None, None)
            data = await response.json()
            open_id = data.get("open_id")
            access_token = data.get("access_token")
            return (open_id,
                    access_token) if open_id and access_token else (None, None)


async def EncRypTMajoRLoGin(open_id, access_token):
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.118.1"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019118695"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    string = major_login.SerializeToString()
    return await encrypted_proto(string)


async def MajorLogin(payload):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr,
                                ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None


async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    Hr['Authorization'] = f"Bearer {token}"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr,
                                ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None


async def DecRypTMajoRLoGin(MajoRLoGinResPonsE):
    proto = MajoRLoGinrEs_pb2.MajorLoginRes()
    proto.ParseFromString(MajoRLoGinResPonsE)
    return proto


async def DecRypTLoGinDaTa(LoGinDaTa):
    proto = PorTs_pb2.GetLoginData()
    proto.ParseFromString(LoGinDaTa)
    return proto


async def DecodeWhisperMessage(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = DEcwHisPErMsG_pb2.DecodeWhisper()
    proto.ParseFromString(packet)
    return proto


async def decode_team_packet(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = sQ_pb2.recieved_chat()
    proto.ParseFromString(packet)
    return proto


async def xAuThSTarTuP(TarGeT, token, timestamp, key, iv):
    uid_hex = hex(TarGeT)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    if uid_length == 9: headers = '0000000'
    elif uid_length == 8: headers = '00000000'
    elif uid_length == 10: headers = '000000'
    elif uid_length == 7: headers = '000000000'
    else:
        print('Unexpected length')
        headers = '0000000'
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"


async def cHTypE(H):
    if not H: return 'Squid'
    elif H == 1: return 'CLan'
    elif H == 2: return 'PrivaTe'


async def SEndMsG(H, message, Uid, chat_id, key, iv):
    TypE = await cHTypE(H)
    if TypE == 'Squid':
        msg_packet = await xSEndMsgsQ(message, chat_id, key, iv)
    elif TypE == 'CLan':
        msg_packet = await xSEndMsg(message, 1, chat_id, chat_id, key, iv)
    elif TypE == 'PrivaTe':
        msg_packet = await xSEndMsg(message, 2, Uid, Uid, key, iv)
    return msg_packet


async def SEndPacKeT(OnLinE, ChaT, TypE, PacKeT):
    if TypE == 'ChaT' and ChaT:
        whisper_writer.write(PacKeT)
        await whisper_writer.drain()
    elif TypE == 'OnLine':
        online_writer.write(PacKeT)
        await online_writer.drain()
    else:
        return 'UnsoPorTed TypE ! >> ErrrroR (:():)'


async def TcPOnLine(ip, port, key, iv, AutHToKen, reconnect_delay=0.5):
    global online_writer, spam_room, whisper_writer, spammer_uid, spam_chat_id, spam_uid, XX, uid, Spy, data2, Chat_Leave
    while True:
        try:
            reader, writer = await asyncio.open_connection(ip, int(port))
            online_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            online_writer.write(bytes_payload)
            await online_writer.drain()
            while True:
                data2 = await reader.read(9999)
                if not data2: break

                if data2.hex().startswith('0500') and len(data2.hex()) > 1000:
                    try:
                        print(data2.hex()[10:])
                        packet = await DeCode_PackEt(data2.hex()[10:])
                        print(packet)
                        packet = json.loads(packet)
                        OwNer_UiD, CHaT_CoDe, SQuAD_CoDe = await GeTSQDaTa(
                            packet)

                        JoinCHaT = await AutH_Chat(3, OwNer_UiD, CHaT_CoDe,
                                                   key, iv)
                        await SEndPacKeT(whisper_writer, online_writer, 'ChaT',
                                         JoinCHaT)

                        # Only send welcome message if group responses are enabled
                        if config_manager.get_group_responses():
                            message = f'[B][C]{get_random_color()}\n- WeLComE To Emote Bot ! '
                            P = await SEndMsG(0, message, OwNer_UiD, OwNer_UiD,
                                              key, iv)
                            await SEndPacKeT(whisper_writer, online_writer,
                                             'ChaT', P)

                    except:
                        if data2.hex().startswith('0500') and len(
                                data2.hex()) > 1000:
                            try:
                                print(data2.hex()[10:])
                                packet = await DeCode_PackEt(data2.hex()[10:])
                                print(packet)
                                packet = json.loads(packet)
                                OwNer_UiD, CHaT_CoDe, SQuAD_CoDe = await GeTSQDaTa(
                                    packet)

                                JoinCHaT = await AutH_Chat(
                                    3, OwNer_UiD, CHaT_CoDe, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer,
                                                 'ChaT', JoinCHaT)

                                # Only send welcome message if group responses are enabled
                                if config_manager.get_group_responses():
                                    player_uid_msg = xMsGFixinG('player_uid')
                                    player_id_msg = xMsGFixinG('909000001')
                                    dev_msg = xMsGFixinG('1onlysarkar')
                                    message = f'[B][C]{get_random_color()}\n- WeLComE To Emote Bot ! \n\n{get_random_color()}- Commands : @a {player_uid_msg} {player_id_msg}\n\n[00FF00]Dev : @{dev_msg}'
                                    P = await SEndMsG(0, message, OwNer_UiD,
                                                      OwNer_UiD, key, iv)
                                    await SEndPacKeT(whisper_writer,
                                                     online_writer, 'ChaT', P)
                            except:
                                pass

            online_writer.close()
            await online_writer.wait_closed()
            online_writer = None

        except Exception as e:
            print(f"- ErroR With {ip}:{port} - {e}")
            online_writer = None
        await asyncio.sleep(reconnect_delay)


async def TcPChaT(ip,
                  port,
                  AutHToKen,
                  key,
                  iv,
                  LoGinDaTaUncRypTinG,
                  ready_event,
                  region,
                  reconnect_delay=0.5):
    print(region, 'TCP CHAT')

    global spam_room, whisper_writer, spammer_uid, spam_chat_id, spam_uid, online_writer, chat_id, XX, uid, Spy, data2, Chat_Leave
    while True:
        try:
            reader, writer = await asyncio.open_connection(ip, int(port))
            whisper_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            whisper_writer.write(bytes_payload)
            await whisper_writer.drain()
            ready_event.set()
            if LoGinDaTaUncRypTinG.Clan_ID:
                clan_id = LoGinDaTaUncRypTinG.Clan_ID
                clan_compiled_data = LoGinDaTaUncRypTinG.Clan_Compiled_Data
                print('\n - TarGeT BoT in CLan ! ')
                print(f' - Clan Uid > {clan_id}')
                print(f' - BoT ConnEcTed WiTh CLan ChaT SuccEssFuLy ! ')
                pK = await AuthClan(clan_id, clan_compiled_data, key, iv)
                if whisper_writer:
                    whisper_writer.write(pK)
                    await whisper_writer.drain()
            while True:
                data = await reader.read(9999)
                if not data: break

                if data.hex().startswith("120000"):

                    msg = await DeCode_PackEt(data.hex()[10:])
                    chatdata = json.loads(msg)
                    try:
                        response = await DecodeWhisperMessage(data.hex()[10:])
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        XX = response.Data.chat_type
                        inPuTMsG = response.Data.msg.lower()
                    except:
                        response = None

                    if response:
                        if inPuTMsG.startswith(("/5")):
                            try:
                                dd = chatdata['5']['data']['16']
                                print('msg in private')
                                message = f"[B][C]{get_random_color()}\n\nAccepT My Invitation FasT\n\n"
                                P = await SEndMsG(response.Data.chat_type,
                                                  message, uid, chat_id, key,
                                                  iv)
                                await SEndPacKeT(whisper_writer, online_writer,
                                                 'ChaT', P)
                                PAc = await OpEnSq(key, iv, region)
                                await SEndPacKeT(whisper_writer, online_writer,
                                                 'OnLine', PAc)
                                C = await cHSq(5, uid, key, iv, region)
                                await asyncio.sleep(0.5)
                                await SEndPacKeT(whisper_writer, online_writer,
                                                 'OnLine', C)
                                V = await SEnd_InV(5, uid, key, iv, region)
                                await asyncio.sleep(0.5)
                                await SEndPacKeT(whisper_writer, online_writer,
                                                 'OnLine', V)
                                E = await ExiT(None, key, iv)
                                await asyncio.sleep(3)
                                await SEndPacKeT(whisper_writer, online_writer,
                                                 'OnLine', E)
                            except:
                                print('msg in squad')

                        if inPuTMsG.startswith('/x/'):
                            CodE = inPuTMsG.split('/x/')[1]
                            try:
                                dd = chatdata['5']['data']['16']
                                print('msg in private')
                                message = f"[B][C]{get_random_color()}\n\nAccepT My Invitation FasT\n\n"
                                P = await SEndMsG(response.Data.chat_type,
                                                  message, uid, chat_id, key,
                                                  iv)
                                await SEndPacKeT(whisper_writer, online_writer,
                                                 'ChaT', P)
                                EM = await GenJoinSquadsPacket(CodE, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer,
                                                 'OnLine', EM)

                            except:
                                print('msg in squad')

                        if inPuTMsG.startswith('/solo'):
                            leave = await ExiT(uid, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer,
                                             'OnLine', leave)

                        if inPuTMsG.strip().startswith('/s'):
                            EM = await FS(key, iv)
                            await SEndPacKeT(whisper_writer, online_writer,
                                             'OnLine', EM)

                        if inPuTMsG.strip().startswith('!e'):

                            try:
                                dd = chatdata['5']['data']['16']
                                print('msg in private')
                                message = f"[B][C]{get_random_color()}\n\nCommand Available OnLy In SQuaD ! \n\n"
                                P = await SEndMsG(response.Data.chat_type,
                                                  message, uid, chat_id, key,
                                                  iv)
                                await SEndPacKeT(whisper_writer, online_writer,
                                                 'ChaT', P)

                            except:
                                print('msg in squad')

                                parts = inPuTMsG.strip().split()
                                print(response.Data.chat_type, uid, chat_id)
                                message = f'[B][C]{get_random_color()}\nACITVE TarGeT -> {xMsGFixinG(uid)}\n'

                                P = await SEndMsG(response.Data.chat_type,
                                                  message, uid, chat_id, key,
                                                  iv)

                                uid2 = uid3 = uid4 = uid5 = None
                                s = False

                                try:
                                    uid = int(parts[1])
                                    uid2 = int(parts[2])
                                    uid3 = int(parts[3])
                                    uid4 = int(parts[4])
                                    uid5 = int(parts[5])
                                    idT = int(parts[5])

                                except ValueError as ve:
                                    print("ValueError:", ve)
                                    s = True

                                except Exception:
                                    idT = len(parts) - 1
                                    idT = int(parts[idT])
                                    print(idT)
                                    print(uid)

                                if not s:
                                    try:
                                        await SEndPacKeT(
                                            whisper_writer, online_writer,
                                            'ChaT', P)

                                        H = await Emote_k(
                                            uid, idT, key, iv, region)
                                        await SEndPacKeT(
                                            whisper_writer, online_writer,
                                            'OnLine', H)

                                        if uid2:
                                            H = await Emote_k(
                                                uid2, idT, key, iv, region)
                                            await SEndPacKeT(
                                                whisper_writer, online_writer,
                                                'OnLine', H)
                                        if uid3:
                                            H = await Emote_k(
                                                uid3, idT, key, iv, region)
                                            await SEndPacKeT(
                                                whisper_writer, online_writer,
                                                'OnLine', H)
                                        if uid4:
                                            H = await Emote_k(
                                                uid4, idT, key, iv, region)
                                            await SEndPacKeT(
                                                whisper_writer, online_writer,
                                                'OnLine', H)
                                        if uid5:
                                            H = await Emote_k(
                                                uid5, idT, key, iv, region)
                                            await SEndPacKeT(
                                                whisper_writer, online_writer,
                                                'OnLine', H)

                                    except Exception as e:
                                        pass

                        # Check if message is private chat (type 2)
                        is_private = False
                        try:
                            dd = chatdata['5']['data']['16']
                            is_private = True
                        except:
                            is_private = False

                        # Secret toggle command (private only)
                        if inPuTMsG == "/mg" and is_private:
                            current = config_manager.get_group_responses()
                            config_manager.set_group_responses(not current)
                            # No response sent (secret command)

                        # Status check command (private only)
                        elif inPuTMsG == "/89" and is_private:
                            status = "ENABLED" if config_manager.get_group_responses(
                            ) else "DISABLED"
                            color = get_random_color()
                            message = f'[B][C]{color}Group Responses\n{color}--------------------\n{color}\n{color}Status: {status}\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                            P = await SEndMsG(response.Data.chat_type, message,
                                              uid, chat_id, key, iv)
                            await SEndPacKeT(whisper_writer, online_writer,
                                             'ChaT', P)

                        # Spam invites command (private only)
                        elif inPuTMsG.startswith('/spm/') and is_private:
                            parts = inPuTMsG.split('/')
                            if len(parts) >= 4:
                                try:
                                    times = int(parts[2])
                                    target_uid = parts[3]
                                    color = get_random_color()
                                    uid_formatted = xMsGFixinG(target_uid)
                                    message = f'[B][C]{color}\n{color} INVITES SENDING\n{color}\n{color}--------------------\n{color}\n{color}Starting invitation process\n{color} \n{color}Total Invites: {times}\n{color}Target Player: {uid_formatted}\n{color} \n{color}Please wait while I send them\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar\n{color}'
                                    P = await SEndMsG(response.Data.chat_type,
                                                      message, uid, chat_id,
                                                      key, iv)
                                    await SEndPacKeT(whisper_writer,
                                                     online_writer, 'ChaT', P)

                                    for i in range(times):
                                        PAc = await OpEnSq(key, iv, region)
                                        await SEndPacKeT(
                                            whisper_writer, online_writer,
                                            'OnLine', PAc)
                                        await asyncio.sleep(
                                            random.uniform(0.15, 0.2))

                                        C = await cHSq(5, int(target_uid), key,
                                                       iv, region)
                                        await SEndPacKeT(
                                            whisper_writer, online_writer,
                                            'OnLine', C)
                                        await asyncio.sleep(
                                            random.uniform(0.15, 0.2))

                                        V = await SEnd_InV(
                                            5, int(target_uid), key, iv,
                                            region)
                                        await SEndPacKeT(
                                            whisper_writer, online_writer,
                                            'OnLine', V)
                                        await asyncio.sleep(
                                            random.uniform(0.15, 0.2))

                                        E = await ExiT(None, key, iv)
                                        await SEndPacKeT(
                                            whisper_writer, online_writer,
                                            'OnLine', E)
                                        await asyncio.sleep(
                                            random.uniform(0.15, 0.2))
                                except:
                                    pass

                        # Set owner UIDs command (private only)
                        elif inPuTMsG.startswith('/uid/'):
                            if not is_private:
                                continue
                            parts = inPuTMsG.split('/')
                            uids = [p for p in parts[2:] if p.strip()]
                            if uids:
                                config_manager.set_owner_uids(uids)
                                color = get_random_color()
                                uid_list = '\n'.join(
                                    [f'{color}{xMsGFixinG(u)}' for u in uids])
                                message = f'[B][C]{color}Owner UID Set\n{color}--------------------\n{color}\n{color}Successfully set {len(uids)}\n{color}owner UID(s)\n{color}\n{uid_list}\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                P = await SEndMsG(response.Data.chat_type,
                                                  message, uid, chat_id, key,
                                                  iv)
                                await SEndPacKeT(whisper_writer, online_writer,
                                                 'ChaT', P)

                        # Create emote command (private only)
                        elif inPuTMsG.startswith(
                                '/e/') and not inPuTMsG.startswith('/emt'):
                            if not is_private:
                                continue
                            parts = inPuTMsG.split('/')
                            if len(parts) >= 4:
                                name = parts[2]
                                code = parts[3]
                                config_manager.add_emote(name, code)
                                color = get_random_color()
                                message = f'[B][C]{color}Emote Command Saved\n{color}--------------------\n{color}\n{color}Command /{name}\n{color}saved successfully with\n{color}emote {code}\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                P = await SEndMsG(response.Data.chat_type,
                                                  message, uid, chat_id, key,
                                                  iv)
                                await SEndPacKeT(whisper_writer, online_writer,
                                                 'ChaT', P)

                        # Remove emote command (private only)
                        elif inPuTMsG.startswith('/rmv/'):
                            if not is_private:
                                continue
                            parts = inPuTMsG.split('/')
                            if len(parts) >= 3:
                                name = parts[2]
                                if config_manager.remove_emote(name):
                                    color = get_random_color()
                                    message = f'[B][C]{color}Emote Removed\n{color}--------------------\n{color}\n{color}Command /{name}\n{color}removed successfully\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                else:
                                    color = get_random_color()
                                    message = f'[B][C]{color}Emote Not Found\n{color}--------------------\n{color}\n{color}Command /{name}\n{color}does not exist\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                P = await SEndMsG(response.Data.chat_type,
                                                  message, uid, chat_id, key,
                                                  iv)
                                await SEndPacKeT(whisper_writer, online_writer,
                                                 'ChaT', P)

                        # List all emotes command (private only)
                        elif inPuTMsG == '/emt':
                            if not is_private:
                                continue
                            all_emotes = config_manager.get_all_emotes()
                            if all_emotes:
                                emote_names = list(all_emotes.keys())
                                chunks = [
                                    emote_names[i:i + 10]
                                    for i in range(0, len(emote_names), 10)
                                ]
                                for chunk in chunks:
                                    message = ' '.join(
                                        [f'/{name}' for name in chunk])
                                    P = await SEndMsG(response.Data.chat_type,
                                                      message, uid, chat_id,
                                                      key, iv)
                                    await SEndPacKeT(whisper_writer,
                                                     online_writer, 'ChaT', P)
                                    await asyncio.sleep(0.3)

                        # Execute all emotes command (private only)
                        elif inPuTMsG.startswith('/all/'):
                            if not is_private:
                                continue
                            parts = inPuTMsG.split('/')
                            if len(parts) >= 3:
                                try:
                                    seconds = float(parts[2])
                                    all_emotes = config_manager.get_all_emotes(
                                    )
                                    owner_uids = config_manager.get_owner_uids(
                                    )

                                    if not owner_uids:
                                        color = get_random_color()
                                        message = f'[B][C]{color}UID Not Found\n{color}--------------------\n{color}\n{color}No UID found\n{color}Please set using\n{color}/uid/{{uid}}\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                        P = await SEndMsG(
                                            response.Data.chat_type, message,
                                            uid, chat_id, key, iv)
                                        await SEndPacKeT(
                                            whisper_writer, online_writer,
                                            'ChaT', P)
                                    elif not all_emotes:
                                        color = get_random_color()
                                        message = f'[B][C]{color}No Emotes Found\n{color}--------------------\n{color}\n{color}No emotes saved\n{color}Add emotes using\n{color}/e/{{name}}/{{code}}\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                        P = await SEndMsG(
                                            response.Data.chat_type, message,
                                            uid, chat_id, key, iv)
                                        await SEndPacKeT(
                                            whisper_writer, online_writer,
                                            'ChaT', P)
                                    else:
                                        color = get_random_color()
                                        message = f'[B][C]{color}Starting All Emotes\n{color}--------------------\n{color}\n{color}Executing {len(all_emotes)} emotes\n{color}Interval: {seconds}s\n{color}UIDs: {len(owner_uids)}\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                        P = await SEndMsG(
                                            response.Data.chat_type,
                                            message, uid, chat_id, key, iv)
                                        await SEndPacKeT(
                                            whisper_writer, online_writer,
                                            'ChaT', P)

                                        for name, code in all_emotes.items():
                                            tasks = [
                                                Emote_k(
                                                    int(owner_uid), int(code),
                                                    key, iv, region)
                                                for owner_uid in owner_uids
                                            ]
                                            packets = await asyncio.gather(
                                                *tasks)
                                            for packet in packets:
                                                await SEndPacKeT(
                                                    whisper_writer,
                                                    online_writer, 'OnLine',
                                                    packet)

                                            color = get_random_color()
                                            message = f'[B][C]{color}Emote Executed\n{color}--------------------\n{color}\n{color}Name: /{name}\n{color}Code: {code}\n{color}\n{color}--------------------'
                                            P = await SEndMsG(
                                                response.Data.chat_type,
                                                message, uid, chat_id, key, iv)
                                            await SEndPacKeT(
                                                whisper_writer, online_writer,
                                                'ChaT', P)
                                            await asyncio.sleep(seconds)

                                        color = get_random_color()
                                        message = f'[B][C]{color}All Emotes Completed\n{color}--------------------\n{color}\n{color}Total: {len(all_emotes)} emotes\n{color}Executed successfully\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                        P = await SEndMsG(
                                            response.Data.chat_type, message,
                                            uid, chat_id, key, iv)
                                        await SEndPacKeT(
                                            whisper_writer, online_writer,
                                            'ChaT', P)
                                except:
                                    pass

                        # Emote sequence command (private only)
                        elif '.' in inPuTMsG and inPuTMsG.startswith(
                                '/') and not any(
                                    inPuTMsG.startswith(x) for x in [
                                        '/uid/', '/e/', '/rmv/', '/help', '/5',
                                        '/x/', '/spm/', '/s', '/mg', '/89',
                                        '/emt', '/all/'
                                    ]):
                            if not is_private:
                                continue
                            parts = inPuTMsG.split('/')
                            sequence = []
                            for part in parts[1:]:
                                if '.' in part:
                                    try:
                                        name, timing = part.rsplit('.', 1)
                                        timing = float(timing)
                                        code = config_manager.get_emote(name)
                                        if code:
                                            sequence.append(
                                                (name, code, timing))
                                    except:
                                        pass

                            if sequence:
                                owner_uids = config_manager.get_owner_uids()
                                if not owner_uids:
                                    color = get_random_color()
                                    message = f'[B][C]{color}UID Not Found\n{color}--------------------\n{color}\n{color}No UID found\n{color}Please set using\n{color}/uid/{{uid}}\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                    P = await SEndMsG(response.Data.chat_type,
                                                      message, uid, chat_id,
                                                      key, iv)
                                    await SEndPacKeT(whisper_writer,
                                                     online_writer, 'ChaT', P)
                                else:
                                    color = get_random_color()
                                    message = f'[B][C]{color}Starting Sequence\n{color}--------------------\n{color}\n{color}Executing {len(sequence)} emotes\n{color}UIDs: {len(owner_uids)}\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                    P = await SEndMsG(response.Data.chat_type,
                                                      message, uid, chat_id,
                                                      key, iv)
                                    await SEndPacKeT(whisper_writer,
                                                     online_writer, 'ChaT', P)

                                    for name, code, timing in sequence:
                                        tasks = [
                                            Emote_k(int(owner_uid), int(code),
                                                    key, iv, region)
                                            for owner_uid in owner_uids
                                        ]
                                        packets = await asyncio.gather(*tasks)
                                        for packet in packets:
                                            await SEndPacKeT(
                                                whisper_writer, online_writer,
                                                'OnLine', packet)

                                        color = get_random_color()
                                        message = f'[B][C]{color}Emote Executed\n{color}--------------------\n{color}\n{color}Name: /{name}\n{color}Code: {code}\n{color}Duration: {timing}s\n{color}\n{color}--------------------'
                                        P = await SEndMsG(
                                            response.Data.chat_type,
                                            message, uid, chat_id, key, iv)
                                        await SEndPacKeT(
                                            whisper_writer, online_writer,
                                            'ChaT', P)
                                        await asyncio.sleep(timing)

                                    color = get_random_color()
                                    message = f'[B][C]{color}Sequence Completed\n{color}--------------------\n{color}\n{color}Total: {len(sequence)} emotes\n{color}Executed successfully\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                    P = await SEndMsG(response.Data.chat_type,
                                                      message, uid, chat_id,
                                                      key, iv)
                                    await SEndPacKeT(whisper_writer,
                                                     online_writer, 'ChaT', P)
                            else:
                                color = get_random_color()
                                message = f'[B][C]{color}Invalid Sequence\n{color}--------------------\n{color}\n{color}No valid emotes found\n{color}Format:\n{color}/{{name}}.{{sec}}/{{name}}.{{sec}}/\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                P = await SEndMsG(response.Data.chat_type,
                                                  message, uid, chat_id, key,
                                                  iv)
                                await SEndPacKeT(whisper_writer, online_writer,
                                                 'ChaT', P)

                        # Team code emote command: @{teamcode}/{name} (private only)
                        elif inPuTMsG.startswith('@') and '/' in inPuTMsG and is_private:
                            parts = inPuTMsG.split('/')
                            if len(parts) >= 2:
                                teamcode = parts[0].replace('@', '')
                                emote_name = parts[1]
                                emote_code = config_manager.get_emote(emote_name)

                                if emote_code:
                                    owner_uids = config_manager.get_owner_uids()
                                    if owner_uids:
                                        try:
                                            # Step 1: Join team
                                            join_packet = await GenJoinSquadsPacket(teamcode, key, iv)
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', join_packet)
                                            await asyncio.sleep(0.3)  # Wait for server to register bot in team

                                            # Step 2: Send emotes to all owner UIDs (instant)
                                            for owner_uid in owner_uids:
                                                emote_packet = await Emote_k(int(owner_uid), int(emote_code), key, iv, region)
                                                await SEndPacKeT(whisper_writer, online_writer, 'OnLine', emote_packet)

                                            # Step 3: Leave team (instant)
                                            leave_packet = await ExiT(None, key, iv)
                                            await SEndPacKeT(whisper_writer, online_writer, 'OnLine', leave_packet)

                                            # Send confirmation message
                                            color = get_random_color()
                                            message = f'[B][C]{color}Team Emote Done\n{color}--------------------\n{color}\n{color}Team: {teamcode}\n{color}Emote: {emote_name}\n{color}Code: {emote_code}\n{color}\n{color}Join → Emote → Leave\n{color}Completed\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                            P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                            await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                        except Exception as e:
                                            print(f"Team emote error: {e}")
                                    else:
                                        color = get_random_color()
                                        message = f'[B][C]{color}UID Not Found\n{color}--------------------\n{color}\n{color}No UID found\n{color}Please set using\n{color}/uid/{{uid}}\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                        P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                        await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                else:
                                    color = get_random_color()
                                    message = f'[B][C]{color}Emote Not Found\n{color}--------------------\n{color}\n{color}Emote "{emote_name}" not found\n{color}Create using\n{color}/e/{{name}}/{{code}}\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)

                        # Post command: post /{uid}/{emotecode}/{teamcode} (private only)
                        elif inPuTMsG.startswith('post /') and is_private:
                            parts = inPuTMsG.replace('post /', '').split('/')
                            if len(parts) >= 3:
                                try:
                                    target_uid = parts[0].strip()
                                    emote_code = parts[1].strip()
                                    teamcode = parts[2].strip()

                                    # Validate numeric inputs
                                    if not target_uid.isdigit() or not emote_code.isdigit():
                                        raise ValueError("UID and emote code must be numeric")

                                    # Step 1: Join team
                                    join_packet = await GenJoinSquadsPacket(teamcode, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', join_packet)
                                    await asyncio.sleep(0.3)  # Wait for server to register bot in team

                                    # Step 2: Send emote to target UID
                                    emote_packet = await Emote_k(int(target_uid), int(emote_code), key, iv, region)
                                    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', emote_packet)

                                    # Step 3: Leave team
                                    leave_packet = await ExiT(None, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', leave_packet)

                                    # Send confirmation message
                                    color = get_random_color()
                                    message = f'[B][C]{color}Post Emote Done\n{color}--------------------\n{color}\n{color}Team: {teamcode}\n{color}Target UID: {target_uid}\n{color}Emote Code: {emote_code}\n{color}\n{color}Join → Emote → Leave\n{color}Completed\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                except Exception as e:
                                    print(f"Post emote error: {e}")
                                    color = get_random_color()
                                    message = f'[B][C]{color}Post Emote Error\n{color}--------------------\n{color}\n{color}Error: {str(e)}\n{color}\n{color}Format: post /{{uid}}/{{emotecode}}/{{teamcode}}\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                            else:
                                color = get_random_color()
                                message = f'[B][C]{color}Invalid Format\n{color}--------------------\n{color}\n{color}Format: post /{{uid}}/{{emotecode}}/{{teamcode}}\n{color}\n{color}Example: post /123456789/909000001/ABCD1234\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)

                        # Execute custom emote command (private only)
                        elif inPuTMsG.startswith('/') and not any(
                                inPuTMsG.startswith(x) for x in
                            [
                                '/uid/', '/e/', '/rmv/', '/help', '/5', '/x/',
                                '/spm/', '/s', '/mg', '/89', '/emt', '/all/'
                            ]) and '.' not in inPuTMsG:
                            if not is_private:
                                continue
                            emote_name = inPuTMsG[1:]
                            emote_code = config_manager.get_emote(emote_name)
                            if emote_code:
                                owner_uids = config_manager.get_owner_uids()
                                if owner_uids:
                                    tasks = [
                                        Emote_k(int(owner_uid),
                                                int(emote_code), key, iv,
                                                region)
                                        for owner_uid in owner_uids
                                    ]
                                    packets = await asyncio.gather(*tasks)
                                    for packet in packets:
                                        await SEndPacKeT(
                                            whisper_writer, online_writer,
                                            'OnLine', packet)

                                    color = get_random_color()
                                    message = f'[B][C]{color}Sent Successfully\n{color}--------------------\n{color}\n{color}Sent successfully\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                    P = await SEndMsG(response.Data.chat_type,
                                                      message, uid, chat_id,
                                                      key, iv)
                                    await SEndPacKeT(whisper_writer,
                                                     online_writer, 'ChaT', P)
                                else:
                                    color = get_random_color()
                                    message = f'[B][C]{color}UID Not Found\n{color}--------------------\n{color}\n{color}No UID found\n{color}Please set using\n{color}/uid/{{uid}}\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                    P = await SEndMsG(response.Data.chat_type,
                                                      message, uid, chat_id,
                                                      key, iv)
                                    await SEndPacKeT(whisper_writer,
                                                     online_writer, 'ChaT', P)

                        # Lag command: #{teamcode}/{time} (private only)
                        elif inPuTMsG.startswith('#') and '/' in inPuTMsG and is_private and not inPuTMsG.startswith('#lag'):
                            parts = inPuTMsG.split('/')
                            if len(parts) >= 2:
                                try:
                                    teamcode = parts[0].replace('#', '')
                                    duration = int(parts[1])

                                    color = get_random_color()
                                    message = f'[B][C]{color}Lag Started\n{color}--------------------\n{color}\n{color}Team: {teamcode}\n{color}Duration: {duration}s\n{color}\n{color}Spamming join/leave\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)

                                    start_time = time.time()
                                    while time.time() - start_time < duration:
                                        join_packet = await GenJoinSquadsPacket(teamcode, key, iv)
                                        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', join_packet)
                                        await asyncio.sleep(0.2)

                                        leave_packet = await ExiT(None, key, iv)
                                        await SEndPacKeT(whisper_writer, online_writer, 'OnLine', leave_packet)
                                        await asyncio.sleep(0.1)

                                    color = get_random_color()
                                    message = f'[B][C]{color}Lag Completed\n{color}--------------------\n{color}\n{color}Team: {teamcode}\n{color}Duration: {duration}s\n{color}\n{color}Finished successfully\n{color}\n{color}--------------------\n{color}\n{color}Follow on Instagram\n{color}@1onlysarkar'
                                    P = await SEndMsG(response.Data.chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(whisper_writer, online_writer, 'ChaT', P)
                                except:
                                    pass

                        # Update help command with group response toggle
                        if inPuTMsG in ("hi", "hello", "fen", "/help"):
                            # Check if we should respond in group chat
                            if not is_private and not config_manager.get_group_responses(
                            ):
                                pass  # Don't respond in group chat if disabled
                            else:
                                uid = response.Data.uid
                                chat_id = response.Data.Chat_ID
                                # Two-part message
                                message1 = '[C][B][00FFFF]━━━━━━━━━━━━\n[ffd319][B]PUBLIC COMMANDS\n[FFFFFF]/help - Show commands\n[FFFFFF]/x/{teamcode} - Join group\n[FFFFFF]/5 - Create 5 player group\n[FFFFFF]/solo - Leave group\n[FFFFFF]!e {uid} {emote_code} - Perform emote\n[C][B][FFB300]━━━━━━━━━━━━'
                                P = await SEndMsG(response.Data.chat_type,
                                                  message1, uid, chat_id, key,
                                                  iv)
                                await SEndPacKeT(whisper_writer, online_writer,
                                                 'ChaT', P)
                                await asyncio.sleep(0.3)

                                message2 = '[C][B][00FFFF]━━━━━━━━━━━━\n[ffd319][B]PREMIUM COMMANDS\n[FFFFFF]/uid/{uid1}/{uid2}/... - Set owner UIDs\n[FFFFFF]/e/{name}/{code} - Create emote\n[FFFFFF]/rmv/{name} - Remove emote\n[FFFFFF]/emt - List all emotes\n[FFFFFF]/{name} - Execute emote\n[FFFFFF]/all/{seconds} - Run all emotes\n[FFFFFF]/spm/{times}/{uid} - Spam invites\n[FFFFFF]/{{name}}.{{sec}}/{{name}}.{{sec}}/ - Emote sequence\n[FFFFFF]@{teamcode}/{name} - Team emote\n[FFFFFF]post /{{uid}}/{{code}}/{{team}} - Post emote\n[FFFFFF]#lag{{teamcode}}/{{time}} - Lag team\n[C][B][FFB300]OWNER: 1onlysarkar\n[00FFFF]━━━━━━━━━━━━\n[FFFFFF]Instagram: @1onlysarkar'
                                P = await SEndMsG(response.Data.chat_type,
                                                  message2, uid, chat_id, key,
                                                  iv)
                                await SEndPacKeT(whisper_writer, online_writer,
                                                 'ChaT', P)
                        response = None

            whisper_writer.close()
            await whisper_writer.wait_closed()
            whisper_writer = None

        except Exception as e:
            print(f"ErroR {ip}:{port} - {e}")
            whisper_writer = None
        await asyncio.sleep(reconnect_delay)


async def execute_post_emote(target_uid, emote_code, teamcode):
    """Shared async function to execute post emote command"""
    global online_writer, whisper_writer

    if not bot_runtime['ready']:
        raise Exception("Bot is not ready yet")

    key = bot_runtime['key']
    iv = bot_runtime['iv']
    region = bot_runtime['region']

    target_uid = str(target_uid).strip()
    emote_code = str(emote_code).strip()
    teamcode = str(teamcode).strip()

    if not target_uid.isdigit() or not emote_code.isdigit():
        raise ValueError("UID and emote code must be numeric")

    join_packet = await GenJoinSquadsPacket(teamcode, key, iv)
    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', join_packet)
    await asyncio.sleep(0.3)

    emote_packet = await Emote_k(int(target_uid), int(emote_code), key, iv, region)
    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', emote_packet)

    leave_packet = await ExiT(None, key, iv)
    await SEndPacKeT(whisper_writer, online_writer, 'OnLine', leave_packet)

    return {
        'success': True,
        'target_uid': target_uid,
        'emote_code': emote_code,
        'teamcode': teamcode
    }


async def api_post_emote(request):
    """HTTP POST /post endpoint"""
    try:
        auth_token = request.headers.get('Authorization')
        api_key = os.getenv('BOT_API_KEY')

        if api_key and auth_token != f'Bearer {api_key}':
            return web.json_response({
                'success': False,
                'error': 'Unauthorized'
            }, status=401)

        data = await request.json()

        uid = data.get('uid')
        emotecode = data.get('emotecode')
        teamcode = data.get('teamcode')

        if not uid or not emotecode or not teamcode:
            return web.json_response({
                'success': False,
                'error': 'Missing required fields: uid, emotecode, teamcode'
            }, status=400)

        result = await execute_post_emote(uid, emotecode, teamcode)

        return web.json_response({
            'success': True,
            'message': 'Post emote executed successfully',
            'data': result
        }, status=200)

    except ValueError as e:
        return web.json_response({
            'success': False,
            'error': str(e)
        }, status=400)
    except Exception as e:
        return web.json_response({
            'success': False,
            'error': f'Internal error: {str(e)}'
        }, status=500)


async def api_post_emote_url(request):
    """HTTP POST /{uid}/{emotecode}/{teamcode} endpoint (URL parameters)"""
    try:
        uid = request.match_info.get('uid')
        emotecode = request.match_info.get('emotecode')
        teamcode = request.match_info.get('teamcode')

        if not uid or not emotecode or not teamcode:
            return web.json_response({
                'success': False,
                'error': 'Missing required fields: uid, emotecode, teamcode'
            }, status=400)

        result = await execute_post_emote(uid, emotecode, teamcode)

        return web.json_response({
            'success': True,
            'message': 'Post emote executed successfully',
            'data': result
        }, status=200)

    except ValueError as e:
        return web.json_response({
            'success': False,
            'error': str(e)
        }, status=400)
    except Exception as e:
        return web.json_response({
            'success': False,
            'error': f'Internal error: {str(e)}'
        }, status=500)


async def api_status(request):
    """HTTP GET /status endpoint"""
    return web.json_response({
        'status': 'running',
        'ready': bot_runtime['ready'],
        'region': bot_runtime.get('region'),
        'message': 'Free Fire Bot is running'
    }, status=200)


async def api_health(request):
    """HTTP GET /health endpoint"""
    return web.json_response({
        'status': 'healthy',
        'service': 'Free Fire Bot'
    }, status=200)


async def start_http_server():
    """Start HTTP API server"""
    app = web.Application()
    app.router.add_post('/post', api_post_emote)
    app.router.add_post('/{uid}/{emotecode}/{teamcode}', api_post_emote_url)
    app.router.add_get('/status', api_status)
    app.router.add_get('/health', api_health)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 5000)
    await site.start()
    print("HTTP API server started on http://0.0.0.0:5000")
    return runner


async def MaiiiinE():
    Uid = os.getenv('FREEFIRE_UID')
    Pw = os.getenv('FREEFIRE_PASSWORD')

    if not Uid or not Pw:
        print(
            "ErroR - Missing FREEFIRE_UID or FREEFIRE_PASSWORD environment variables!"
        )
        return None

    open_id, access_token = await GeNeRaTeAccEss(Uid, Pw)
    if not open_id or not access_token:
        print("ErroR - InvaLid AccounT")
        return None

    PyL = await EncRypTMajoRLoGin(open_id, access_token)
    MajoRLoGinResPonsE = await MajorLogin(PyL)
    if not MajoRLoGinResPonsE:
        print("TarGeT AccounT => BannEd / NoT ReGisTeReD ! ")
        return None

    MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE)
    UrL = MajoRLoGinauTh.url
    print(UrL)
    region = MajoRLoGinauTh.region

    ToKen = MajoRLoGinauTh.token
    TarGeT = MajoRLoGinauTh.account_uid
    key = MajoRLoGinauTh.key
    iv = MajoRLoGinauTh.iv
    timestamp = MajoRLoGinauTh.timestamp

    LoGinDaTa = await GetLoginData(UrL, PyL, ToKen)
    if not LoGinDaTa:
        print("ErroR - GeTinG PorTs From LoGin DaTa !")
        return None
    LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
    OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
    ChaTPorTs = LoGinDaTaUncRypTinG.AccountIP_Port
    OnLineiP, OnLineporT = OnLinePorTs.split(":")
    ChaTiP, ChaTporT = ChaTPorTs.split(":")
    acc_name = LoGinDaTaUncRypTinG.AccountName
    #print(acc_name)
    print(ToKen)
    equie_emote(ToKen, UrL)
    AutHToKen = await xAuThSTarTuP(int(TarGeT), ToKen, int(timestamp), key, iv)
    ready_event = asyncio.Event()

    bot_runtime['key'] = key
    bot_runtime['iv'] = iv
    bot_runtime['region'] = region

    task1 = asyncio.create_task(
        TcPChaT(ChaTiP, ChaTporT, AutHToKen, key, iv, LoGinDaTaUncRypTinG,
                ready_event, region))

    await ready_event.wait()
    await asyncio.sleep(1)

    bot_runtime['ready'] = True

    task2 = asyncio.create_task(
        TcPOnLine(OnLineiP, OnLineporT, key, iv, AutHToKen))
    os.system('clear')
    print(render('1onlysarkar', colors=['white', 'green'], align='center'))
    print('')
    #print(' - ReGioN => {region}'.format(region))
    print(
        f" - BoT STarTinG And OnLine on TarGet : {TarGeT} | BOT NAME : {acc_name}\n"
    )
    print(f" - BoT sTaTus > GooD | OnLinE ! (:")
    print(f" - Instagram > @1onlysarkar ! (:")
    await asyncio.gather(task1, task2)


async def StarTinG():
    http_runner = await start_http_server()
    print("HTTP API server started on http://0.0.0.0:5000")

    while True:
        try:
            bot_runtime['ready'] = False
            await asyncio.wait_for(MaiiiinE(), timeout=7 * 60 * 60)
        except asyncio.TimeoutError:
            print("Token ExpiRed ! , ResTartinG in 30 seconds...")
            await asyncio.sleep(30)
        except Exception as e:
            print(f"ErroR TcP - {e} => ResTarTinG in 30 seconds...")
            await asyncio.sleep(30)


if __name__ == '__main__':
    asyncio.run(StarTinG())
