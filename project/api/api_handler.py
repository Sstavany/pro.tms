from flask import Flask, request, jsonify
import telebot
import threading
import time
import json
import os
import html
import requests
import binascii
import random
import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from protobuf_decoder.protobuf_decoder import Parser

app = Flask(__name__)

# Telegram Bot Token
TOKEN = os.getenv("TOKEN", "7597061572:AAHF-Ljkara7fx2Xn0vvFIsuX8jHpcmELlQ")
bot = telebot.TeleBot(TOKEN)

# List of allowed group IDs
groups_ids = [-1002652136437]

# File for storing user data
DATA_FILE = "users.json"

# Constants from byte.py
da = 'f2212101'
dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', '，有人', 'fb', 'fc', 'fd', 'fe', 'ff']
x = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
numbers = [902000208, 902000209, 902000210, 902000211]

# Encryption and Protobuf Functions
def generate_random_hex_color():
    top_colors = [
        "FF4500", "FFD700", "32CD32", "87CEEB", "9370DB", "FF69B4", "8A2BE2", "00BFFF", "1E90FF", "20B2AA",
        "00FA9A", "008000", "FFFF00", "FF8C00", "DC143C", "FF6347", "FFA07A", "FFDAB9", "CD853F", "D2691E",
        "BC8F8F", "F0E68C", "556B2F", "808000", "4682B4", "6A5ACD", "7B68EE", "8B4513", "C71585", "4B0082",
        "B22222", "228B22", "8B008B", "483D8B", "556B2F", "800000", "008080", "000080", "800080", "808080",
        "A9A9A9", "D3D3D3", "F0F0F0"
    ]
    return random.choice(top_colors)

def encrypt_packet(plain_text, key=None, iv=None):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def dec_to_hex(ask):
    ask_result = hex(ask)
    final_result = str(ask_result)[2:]
    if len(final_result) == 1:
        final_result = "0" + final_result
    return final_result

class ParsedResult:
    def __init__(self, field, wire_type, data):
        self.field = field
        self.wire_type = wire_type
        self.data = data

class ParsedResultEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ParsedResult):
            return {"field": obj.field, "wire_type": obj.wire_type, "data": obj.data}
        return super().default(obj)

def bunner_():
    return random.choice(numbers)

def create_varint_field(field_number, value):
    field_header = (field_number << 3) | 0
    return encode_varint(field_header) + encode_varint(value)

def create_length_delimited_field(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return encode_varint(field_header) + encode_varint(len(encoded_value)) + encoded_value

def create_protobuf_packet(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = create_protobuf_packet(value)
            packet.extend(create_length_delimited_field(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(create_varint_field(field, value))
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(create_length_delimited_field(field, value))
    return packet

def encode_varint(number):
    if number < 0:
        raise ValueError("Number must be non-negative")
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes)

def Encrypt_ID(number):
    number = int(number)
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes).hex()

def decrypt_api(cipher_text):
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(bytes.fromhex(cipher_text)), AES.block_size)
    return plain_text.hex()

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        if result.wire_type == "varint":
            field_data['data'] = result.data
        elif result.wire_type == "string":
            field_data['data'] = result.data
        elif result.wire_type == "bytes":
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_dict = parse_results(parsed_results)
        json_data = json.dumps(parsed_results_dict, cls=ParsedResultEncoder)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None

# Functions from kk1.py
def fetch_token():
    url = "https://ffwlxd-access-jwt.vercel.app/api/get_jwt?guest_uid=4085573226&guest_password=5B7AF19BC8F1B01615B5FB5E2ABC8969A69E8A6523DD2C32AB6A5A64EB9171B9"
    try:
        response = requests.get(url)
        print("📩 استجابة API الكاملة:", response.text)
        if response.status_code == 200:
            data = json.loads(response.text)
            token = data.get("BearerAuth")
            if token:
                print("✅ تم جلب التوكن بنجاح:", token)
                return token
            else:
                print("⚠️ التوكن المستلم فارغ!")
                return None
        else:
            print(f"⚠️ فشل في جلب التوكن، كود الخطأ: {response.status_code}, الرد: {response.text}")
            return None
    except Exception as e:
        print("⚠️ خطأ أثناء جلب التوكن:", e)
        return None

def update_token():
    global TOKEN
    while True:
        new_token = fetch_token()
        if new_token:
            TOKEN = new_token
            print("✅ تم تحديث التوكن بنجاح!")
        else:
            print("⚠️ لم يتم تحديث التوكن، سيتم المحاولة لاحقًا.")
        time.sleep(5 * 60 * 60)

def send_friend_request(player_id):
    if not TOKEN:
        msg = "⚠️ التوكن غير متاح حاليًا، حاول لاحقًا."
        print(msg)
        return msg
    print(f"🔑 استخدام التوكن: {TOKEN}")
    encrypted_id = Encrypt_ID(player_id)
    payload = f"08a7c4839f1e10{encrypted_id}1801"
    encrypted_payload = encrypt_api(payload)
    print(f"🔍 player_id: {player_id}")
    print(f"🔍 encrypted_id: {encrypted_id}")
    print(f"🔍 payload: {payload}")
    print(f"🔍 encrypted_payload: {encrypted_payload}")
    url = "https://clientbp.ggblueshark.com/RequestAddingFriend"
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB50",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": str(len(encrypted_payload) // 2),
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-N975F Build/PI)",
        "Host": "clientbp.ggblueshark.com",
        "Connection": "close",
        "Accept-Encoding": "gzip, deflate, br"
    }
    try:
        response = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload))
        if response.status_code == 200:
            msg = "✅ تم إرسال طلب الصداقة بنجاح!"
            print(msg)
            return msg
        else:
            msg = f"⚠️ فشل إرسال طلب الصداقة. رمز الاستجابة: {response.status_code}.\n📩 استجابة الخادم: {response.text}"
            print(msg)
            return msg
    except Exception as e:
        msg = f"⚠️ حدث خطأ أثناء إرسال الطلب: {str(e)}"
        print(msg)
        return msg

def remove_friend(player_id):
    if not TOKEN:
        msg = "⚠️ التوكن غير متاح حاليًا، حاول لاحقًا."
        print(msg)
        return msg
    print(f"🔑 استخدام التوكن: {TOKEN}")
    encrypted_id = Encrypt_ID(player_id)
    payload = f"08a7c4839f1e10{encrypted_id}1801"
    encrypted_payload = encrypt_api(payload)
    print(f"🔍 player_id: {player_id}")
    print(f"🔍 encrypted_id: {encrypted_id}")
    print(f"🔍 payload: {payload}")
    print(f"🔍 encrypted_payload: {encrypted_payload}")
    url = "https://clientbp.ggblueshark.com/RemoveFriend"
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB50",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": str(len(encrypted_payload) // 2),
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-N975F Build/PI)",
        "Host": "clientbp.ggblueshark.com",
        "Connection": "close",
        "Accept-Encoding": "gzip, deflate, br"
    }
    try:
        response = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload))
        if response.status_code == 200:
            msg = "✅ تم حذف الصديق بنجاح!"
            print(msg)
            return msg
        else:
            msg = f"⚠️ فشل حذف الصديق. رمز الاستجابة: {response.status_code}.\n📩 استجابة الخادم: {response.text}"
            print(msg)
            return msg
    except Exception as e:
        msg = f"⚠️ حدث خطأ أثناء إرسال الطلب: {str(e)}"
        print(msg)
        return msg

def Get_player_information(uid):
    if not TOKEN:
        return "⚠️ التوكن غير متاح حاليًا، حاول لاحقًا."
    print(f"🔑 استخدام التوكن: {TOKEN}")
    TARGET = bytes.fromhex(encrypt_api(f"08{Encrypt_ID(uid)}1007"))
    url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB50",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-N975F Build/PI)",
        "Host": "clientbp.common.ggbluefox.com",
        "Connection": "close",
        "Accept-Encoding": "gzip, deflate, br",
    }
    try:
        response = requests.post(url, headers=headers, data=TARGET)
        if response.status_code == 200:
            hex_response = binascii.hexlify(response.content).decode('utf-8')
            json_result = get_available_room(hex_response)
            parsed_data = json.loads(json_result)
            player_info = {
                "🆔 أيدي اللاعب": parsed_data["1"]["data"]["1"]["data"],
                "👤 اسم اللاعب": parsed_data["1"]["data"]["3"]["data"],
                "👍 عدد اللايكات": parsed_data["1"]["data"]["21"]["data"],
                "🎚️ مستوى اللاعب": parsed_data["1"]["data"]["6"]["data"],
                "📅 تاريخ إنشاء الحساب": datetime.datetime.fromtimestamp(parsed_data["1"]["data"]["44"]["data"]).strftime("%Y-%m-%d %H:%M:%S"),
            }
            return json.dumps(player_info, indent=4, ensure_ascii=False)
        else:
            return f"⚠️ فشل في جلب المعلومات، كود الخطأ: {response.status_code}"
    except Exception as e:
        print("⚠️ خطأ في معالجة البيانات:", e)
        return "⚠️ حدث خطأ أثناء تحليل بيانات اللاعب."

# Panel Functions
def load_users():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r", encoding="utf-8") as file:
            try:
                data = json.load(file)
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                pass
    return {}

def save_users():
    with open(DATA_FILE, "w", encoding="utf-8") as file:
        json.dump(users, file, ensure_ascii=False, indent=4)

def is_allowed_group(message):
    return message.chat.id in groups_ids

def format_remaining_time(expiry_time):
    remaining_seconds = int(expiry_time - time.time())
    if remaining_seconds <= 0:
        return "انتهت الصلاحية"
    days = remaining_seconds // 86400
    hours = (remaining_seconds % 86400) // 3600
    return f"{days} أيام {hours} ساعات"

def get_player_name(uid):
    try:
        player_info = Get_player_information(uid)
        if "اسم اللاعب" in player_info:
            name_line = [line for line in player_info.split("\n") if "اسم اللاعب" in line]
            if name_line:
                return name_line[0].split(":")[1].strip()
        return "Unknown"
    except Exception as e:
        print(f"⚠️ خطأ في جلب الاسم: {e}")
        return "Unknown"

def remove_expired_users():
    current_time = time.time()
    expired_users = [uid for uid, data in users.items() if data["expiry"] <= current_time]
    for uid in expired_users:
        print(f"🔴 حذف المستخدم {uid} لانتهاء المهلة عند بدء التشغيل")
        response = remove_friend(str(uid))
        print(f"📩 استجابة حذف المستخدم {uid}: {response}")
        del users[uid]
    save_users()

def check_expired_users():
    while True:
        current_time = time.time()
        expired_users = [uid for uid, data in users.items() if data["expiry"] <= current_time]
        for uid in expired_users:
            print(f"⏳ حذف المستخدم {uid} لانتهاء المهلة أثناء التشغيل")
            response = remove_friend(str(uid))
            print(f"📩 استجابة حذف المستخدم {uid}: {response}")
            del users[uid]
        save_users()
        time.sleep(60)

# Initialize users
users = {}
if os.path.exists(DATA_FILE):
    os.remove(DATA_FILE)
save_users()

# Initialize token and start token update thread
TOKEN = fetch_token()
threading.Thread(target=update_token, daemon=True).start()
threading.Thread(target=check_expired_users, daemon=True).start()

@app.route('/', methods=['POST'])
def handle_command():
    data = request.get_json()
    command = data.get('command', '')
    chat_id = groups_ids[0]

    class Message:
        def __init__(self):
            self.chat = type('obj', (), {'id': chat_id})
            self.text = command

    message = Message()

    if not is_allowed_group(message):
        return jsonify({'message': 'غير مسموح بالوصول من هذه المجموعة'})

    if command.startswith('/add'):
        try:
            _, user_id, days = command.split()
            user_id = int(user_id)
            days = int(days)
            if days <= 0:
                raise ValueError("عدد الأيام يجب أن يكون موجبًا")
            response = send_friend_request(str(user_id))
            if "✅" in response:
                expiry_time = time.time() + (days * 86400)
                name = get_player_name(user_id)
                users[str(user_id)] = {"expiry": expiry_time, "name": name}
                save_users()
                return jsonify({'message': f"✅ تم إضافة اللاعب {name} (ID: {user_id}) بصلاحية {days} أيام.\n📩 تم إرسال طلب الصداقة.\n📩 استجابة الخادم: {response}"})
            else:
                return jsonify({'message': f"⚠️ لم يتم إضافة المستخدم إلى البوت بسبب خطأ أثناء إرسال طلب الصداقة.\n📩 استجابة الخادم: {response}"})
        except ValueError as e:
            return jsonify({'message': f"❌ الاستخدام الصحيح:\n/add id الأيام\nمثال: /add 12345678 3\nخطأ: {str(e)}"})
        except Exception as e:
            return jsonify({'message': "❌ الاستخدام الصحيح:\n/add id الأيام\nمثال: /add 12345678 3"})

    elif command.startswith('/remove'):
        try:
            _, user_id = command.split()
            user_id = str(int(user_id))
            if user_id in users:
                response = remove_friend(user_id)
                if "✅" in response:
                    del users[user_id]
                    save_users()
                    return jsonify({'message': f"✅ تمت إزالة المستخدم {user_id} بنجاح.\n🗑️ تم حذف الصديق من القائمة.\n📩 استجابة الخادم: {response}"})
                else:
                    return jsonify({'message': f"⚠️ لم يتم حذف المستخدم من البوت بسبب خطأ في الحذف من اللعبة.\n📩 استجابة الخادم: {response}"})
            else:
                return jsonify({'message': "❌ المستخدم غير موجود في القائمة."})
        except Exception as e:
            return jsonify({'message': "❌ الاستخدام الصحيح:\n/remove id\nمثال: /remove 12345678"})

    elif command == '/list':
        if not users:
            return jsonify({'message': "📌 لا يوجد لاعبين مضافين بعد!"})
        message_text = ""
        for user_id, data in users.items():
            remaining_time = format_remaining_time(data["expiry"])
            name = html.unescape(data["name"])
            message_text += f"👤 {name}\n🆔 {user_id}\n⏳ {remaining_time}\n───────────────────\n"
        return jsonify({'message': message_text})

    else:
        return jsonify({'message': "❌ أمر غير معروف. استخدم /add, /remove, أو /list"})

if __name__ == '__main__':
    app.run()