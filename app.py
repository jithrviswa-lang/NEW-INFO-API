import asyncio
import base64
import json
import struct
import threading
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

# ---------------------------------------------------------------------------
# Multi-account pools — each account rotates independently.
# ---------------------------------------------------------------------------
ACCOUNTS = {
    "BD": [
        {"uid": "4920329755", "password": "62c76f6b13e37c1de7d1853402f3dbec79309171be1c51456dbf1c9d60dfa139"},
        {"uid": "4920329843", "password": "a4d1286ba60c220e02d467cb3fd1b7a5989430b4c4bcc19e3a812f5d410735ee"},
        {"uid": "4920329853", "password": "264b038634c18b9f2b534e08c8acb88ecde5841de764bd8bc066b6f7586684f6"},
        {"uid": "4920329766", "password": "4f50608d496f95f6dbc658bd5754784539aff29b4f3d7e7e910bd0f9d55e92e1"},
        {"uid": "4920329795", "password": "1d1b86c17d3b8d0d7950181e06ff4b167ecf26b4de46062bf5cd75ea65f5fbe9"},
        {"uid": "4920331098", "password": "b464e7b5337ae4e89504ea4040d59a9a4977c4475933573f60fe88ae311ec0ec"},
        {"uid": "4920331614", "password": "ec22bdc589bff9c4337a758b2061f8d4e333fbefb70b0cda11569c08c09598c8"},
        {"uid": "4920331899", "password": "838a8ffa70289838801abca6ad1803fcbf78ae1f7532393533242f1779709fe0"},
        {"uid": "4920332006", "password": "7a1fda0b519dfd9b4f72aa6c2b32054bee793004fe82774b73193ec4852036d8"},
        {"uid": "4920332049", "password": "7d6c780213dd7050b7eedb0ca9b8f32d5bb3f2dae93babce09e8ef23b05421ea"},
        {"uid": "4920332300", "password": "cf85b5dbe243757bcf760f5bd50d5f5379db0a5d0ad0e5821c2e40d59f6506db"},
        {"uid": "4920332276", "password": "f0b1728673cefef9abbba86d28a195c8e63672846b2dfc82ba1c0774a9e21464"},
        {"uid": "4920333004", "password": "cd7af663440d9d0f8f7802f80e9e818ff8cccf49509a6b649bc6fd47d034530e"},
        {"uid": "4920333059", "password": "d92a7c893b9a429bfb3c4653b35d090218d3321514b29eca21bc903cb24b29c7"},
        {"uid": "4920333486", "password": "083e24c3134fdfb21f693ff0e7b75b69c987e38027e7bd38fecc17ad460c6443"},
        {"uid": "4920333822", "password": "412779b759da315c62f3f3cba9791911fbb4ef8deaa013453f64d12befaee71f"},
        {"uid": "4920337458", "password": "07e282134e749ff0b433c8833d48e3b5fa2171b9af77351e30941e86d25e1f04"},
        {"uid": "4920337791", "password": "626bcfe7442b664cd4af5ed4ed3703f62c41bc723de9af56af14d8fc9e70c198"},
        {"uid": "4920338620", "password": "ae4bc5b0cdb1fab8b3f892772dbeedd6584fb8122ed90b2489a51d14eb3d24c2"},
        {"uid": "4920339930", "password": "c7e34929dae217e7f0d7e44397287e40c6ed5f86c5a3c29ac5897bdc49dd6f23"},
        {"uid": "4920339946", "password": "c6300176700bfcbf75861f464b3ec76c796b16521a88424fa7b675ac0b7b2590"},
        {"uid": "4920340759", "password": "f5a00390982074b45a299254361a25923796a0dd4ec374706e7e62d654edeb8c"},
        {"uid": "4920340848", "password": "a5cf411a9cfe7b4fe5211314189db4267f5b7433f38e6e58b6f354a21bbcf016"},
        {"uid": "4920341058", "password": "22ad5f9d79e11f9750a965ba4bb72e5ef500eb2b7c489ce749c3877573d83bad"},
        {"uid": "4920340913", "password": "aa92b514d17b3d95c3cc676ff39eddc1fdc6702af6c1297d7c2f6e12ec9fe00f"},
        {"uid": "4920341248", "password": "fcf827c1e4519c3ede5941dd9ac029b434b328cadbb5ab6b5a6f00a7eecc570c"},
        {"uid": "4920341848", "password": "20b35ff5318b2e09f2fd92164c3aefb5e5714505273200b7ae5cc0a65164f994"},
        {"uid": "4920341240", "password": "699b9bf79c6727c22c42d5b3551ecb62c5492965a623319545d2e9da59675984"},
        {"uid": "4920341719", "password": "2c434f4f57eae913e41675772015673ac781f5d0ce11eedf6b7749a7a86d2741"},
        {"uid": "4920341549", "password": "d0827467f0f4136885ea682a60eb3c4e30fd91cbf9f6635089a576505665a797"},
        {"uid": "4920342349", "password": "a8fc275492d7cc38dcc1b9af06874dd3b7bf1d58f98880e5202abbbda5b44d41"},
        {"uid": "4920342297", "password": "9a9d7f7de0f65609586e5ba7149e18f04c60cb85fc0b7af58f22164a6b362c1f"},
        {"uid": "4920342585", "password": "174f44281bdecf1822d489e5b528822c1857e04f180cc4543c4c51214a1baa90"},
        {"uid": "4920342422", "password": "caeb5e02a9014e8773e5ec510d9bcc5e15c3f52da402cf602e2c8cde2aeab07c"},
        {"uid": "4920342880", "password": "81bba0a087ff7d9d78d4456f6c40cf621c0ba554ec26e55b40123d9e83919dcc"},
        {"uid": "4920342989", "password": "25ba6b56899efda198b89427595bfdcaa350ef4744d314cbaa3ece349a3aadac"},
        {"uid": "4920343413", "password": "d6d8a6819722c6aa8f1387fbd58315b793d0b2f446c844bb15e599e172fe59bb"},
        {"uid": "4920343331", "password": "37545fe594455495c70e220f589d3e3ce3560f04dfdc4090703421f7bcae7603"},
        {"uid": "4920329879", "password": "0af15604308f89d8623e0ac7d4033ea7e782f1fd87d27972700609846d1b49a1"},
        {"uid": "4920330119", "password": "f3cec1cf9fb091db5726c117d5597ca766d5b3a93772d3e7c9885b973593b7c4"},
        {"uid": "4920330091", "password": "73071968b99d603112e5a0129d18499d7301d2d57f38b1da8d4acfeabc27ced3"},
        {"uid": "4920331304", "password": "0b4b756b75f2078a5e309b19bb071e6a13500a36ac20d3d7cb5f00fbf43ea946"},
        {"uid": "4920331873", "password": "15b5d60ba892db330655b58dbf6b4c9c861034adbdc3a78ef825141644a3ce93"},
        {"uid": "4920331743", "password": "1fd0c3b43b1ac548b52471e39c9ffa95663e813517ec74e296ca3c815cf3e584"},
        {"uid": "4920331803", "password": "cf7739e449b4493837f412b7679426a71d3e06cb42af34c46509fcc9b27ad8f2"},
        {"uid": "4920333256", "password": "dd659c6e35ddfcb7ff4a34595f805522078cb1ffce8dff83795b79e70d4e99bf"},
        {"uid": "4920333314", "password": "9079db015dfc8ea98bbe511253c04e7daf2917b07e0d6786bb6c386f89f2812f"},
        {"uid": "4920333645", "password": "bcdff966dbaf0e3e4e1794b8c6f969039f62e74b72667518ccaef00003e62b37"},
        {"uid": "4920338124", "password": "a2fbb515781ad931787c239e5961d509dadd502ce591b50431337cd3caa16acb"},
        {"uid": "4920341635", "password": "d94919a84eef210f129e95677a8333c659ab0cbd358894b58fc69012603c28eb"},
    ],
    "IND": [
        {"uid": "6095025608", "password": "2295E82237BB4DAD95668F3DCCCA3F19C4813CB2EEFFEA362CEF24BA2FA188B5"},
        {"uid": "6095047850", "password": "92C281EA07A3042739123314409A64F513C623F4A0BF4D9E52B1E11425801C61"},
        {"uid": "6095024035", "password": "41F7EC0BDF3D562BCDBE478559B9DE3A681A299E1E1A3E57894A5AD79457A8E4"},
        {"uid": "6095048744", "password": "FEEEBD2D3AAB85F0B6D2037AB36EA74BC60D01EDE8A02B0F49220753E5465E44"},
        {"uid": "6095025456", "password": "B29EA3EABA8CF43A103997B15D48304374F52553E6B43F88D065325CDDFA24DD"},
        {"uid": "6095051316", "password": "15F641C8C07D3CC0E38F019B8983F915DC440EF9906EA7C43C7EA44C19495617"},
        {"uid": "6095047869", "password": "8D9AEC0CA3E8B3402A9515CE85699DC099AB1F8D3852B4E7105109E86F798437"},
        {"uid": "6095083223", "password": "DA9985EA9EC08D80FB8E77A53766DC942E5787CA5267C9434BA1644AC4E36222"},
        {"uid": "6095049583", "password": "4033D2D34B13667138A9C11FBC224EC34E9CFB013496F6083725E1DC14BDFD52"},
        {"uid": "6095060749", "password": "FF46B5B8A085BA5FE3444EB6547A196971763C3B4C0402220D6C77F9955A6DAA"},
        {"uid": "6095108252", "password": "FC1B21F1F844EF887065FD3B0D8197EA1345C34F2637F7F5F658C453ED2076EB"},
        {"uid": "6095114087", "password": "9CE3B3D34F0A240288C936E2E3A0539990D5508EBCE87A3B37FCBD1859378434"},
        {"uid": "6095092432", "password": "A80E1E950A6C93FDEF9EDE7DC6BD564DA485E91EF7942133C012B1B620791722"},
        {"uid": "6095109347", "password": "91CDF0CB782DE04581EAEC9F6C6D9CED3E1E96CDFD6BC27D9F863F78BA54A794"},
        {"uid": "6095087017", "password": "5AEE02A9F8F7B6F1C84C4A4FCA74603954524AFF7DEA6E994E6D903FD530348D"},
        {"uid": "6095118870", "password": "29AF499752BA5EAA405FF2D526AE2A19BA8E1EBDD0C10BC6E9B2987B813425C3"},
        {"uid": "6095139670", "password": "926671E203388D900FB81C481D2A2A3F02042DDC72462B0954B865C875D32A15"},
        {"uid": "5969193949", "password": "52142DF07F065030DE33A57C6336CC10B749B0C7D2FCFF5F86B9A611BB314CB9"},
        {"uid": "6095139354", "password": "DB73129CC18E0047B0A372AD562000B343936FB4245A0002B87CCEABFE87B3CF"},
        {"uid": "6095137591", "password": "63CA7D41B1797898883A4FDAC79E55E73B6A4B3E29F7834500ABADEE86D96D28"},
        {"uid": "5969201911", "password": "110EB771D3977F891CAA309CD623F3D03379E970BE6DFEA7FD9A022D160FD514"},
        {"uid": "6095120444", "password": "43FB3FC8561456064EDFC81B436C5C0C20022B7FC601B7E5EC67A40D9334BD7E"},
        {"uid": "5969206796", "password": "B580F317385E21E4CE0B0F65074698EA1C6F6EB01D0A1904F95CDB4C01962571"},
        {"uid": "6095146187", "password": "6B0AEC62C508B7CE357737246A1103A20B5870DD390DBE2046FC2ACDFF394C3A"},
        {"uid": "5969205224", "password": "9B542C12FB3B202CC923AF9F319B6A16A92D263DB5CBE935726E2EBEE14A36FF"},
        {"uid": "6095143145", "password": "DA3C5B5A0FAF6E9F003DAE2F345454057F65395A79E0305F05AD2A17D0A0B0F6"},
        {"uid": "6095168600", "password": "D982891330AE6F4DCCDBCCF52EE8FBCF9E7E3FE446422BF912D8155EEF1489FA"},
        {"uid": "6095137433", "password": "CB0E398F59F4F54029C145711242E6C4072367D7AC3A64F1E8B2E95CD9729551"},
        {"uid": "5969203033", "password": "0910EDC47DF43B00C047E5E09A22D06DB2EE910B2D1C7C432FF30BBD9D0A37D9"},
        {"uid": "6095145932", "password": "4811DF278BDA2FB44552C93262EB5CAC42DC56D328F00ABB04761B91E9CE0E8D"},
        {"uid": "5969203875", "password": "20AB37C28E6F428EA503AA3027D27F0BEC97F9D5E32A9ABC89B4FACD467BA9F5"},
        {"uid": "6095182661", "password": "7A2E866772B91E91BA728EE518FE6FA77C40D9A0393578A6D7C1131D439F64DD"},
        {"uid": "6095182844", "password": "2E79DF390408FD8CAFCA629E7CDBCCBC52D8FBDA778F9853827A2EBFF07F8750"},
        {"uid": "6095171071", "password": "E16969C63A1A6780E450D18544464D039004EEDB261872E0F1D3336E8C4F628A"},
        {"uid": "5969208100", "password": "A19AE95850DCF8028DADD95F8CDDEEA8EB907E8E4168FA5E2517177D15D4CEBA"},
        {"uid": "6095182664", "password": "9E95886BF0A0DB1D23472A1D04104B9E2611E8383B148C724140D6FA9DFC176A"},
        {"uid": "6095167483", "password": "37BC1AC5BB00AD5D3264E712861B451068FD21C7DAD080646269421329C7BD56"},
        {"uid": "6095178475", "password": "6D95E5E75605B0268EE06D6C01BE3CE7075F27975991C64FD96B1DAED0884968"},
        {"uid": "6095184536", "password": "9EBD1D5AA78A3BFF4B82D5B03B178F18DF24439AD16A6962F9A0E18D48A1F93C"},
        {"uid": "6095191839", "password": "B643F6119DAD83AC78B7AD92CB97A7F88DE09D6B9F31FD08B920A3FA4EFBD56D"},
        {"uid": "6095192539", "password": "515426BCE2D5AB6A6A250934D9B13950F8E3D378C05896D42B7B71C6BCA5E292"},
        {"uid": "6095190783", "password": "8E53D1D4D568C7FCA1D2045CEF7FA4C9A9D3F8CB4D7B4732B963F6D1EE6F9079"},
        {"uid": "6094979755", "password": "D76F090ACE3D2DD8DE040DC8F7A19B218BA5400E07CDD9FA602218DFD555A246"},
        {"uid": "6094979296", "password": "C6C7A005A27A68058D349ABFC79995CE93078DCB6F88C1C5B1C0E8A0BDCA1702"},
        {"uid": "6095195393", "password": "C6033B6C91AC08DF8300ACC3AAA900429370CAD350F6A3DE25ECE0CEA3E71C94"},
        {"uid": "6095194394", "password": "D2DE5F0240CD2396727C2689D95C4097D9CB78E16A13A7B2661AAAD66E1ADA29"},
        {"uid": "6095194476", "password": "7B7DCEBBCDF5B27DE8DC4D6E5B5B84DA7D1762F6E60A77EB4514C2A6317BA0FA"},
        {"uid": "6094982591", "password": "37A1F25E332B5FF088E56A61477DA283F2AE3222FBB4F31D1CE3ADB806E48869"},
        {"uid": "6094994686", "password": "24C3DE9CC9F573197891C1ED962821D551D7DD8B7CEA8F7380C614BDB9ACAE83"},
        {"uid": "6095198428", "password": "A808215B974FA2EF605423969CE84060DE678F2D10BFCF06EC1DA4E20D25F8D9"},
    ],
    "BR": [
        {"uid": "5969038823", "password": "2A600A4F065E3D35F9CBBBC08AD77D0A79E3609DCB917403E7B439C8472E721E"},
        {"uid": "5969041544", "password": "CBEA15AF9D0EBC0AC6B25B1DAC593DBBF19334141604022EEBFEA44895B891B6"},
        {"uid": "5969063798", "password": "E3DE1297E3731B128602831DEB2CD98C7CFD0399F9539268D1C9537C7511E128"},
        {"uid": "5969059423", "password": "3D94D0FC7C4CD7885DFF8006D34DFE7A0DD616585ABBF8CD7854E32CCB9E3BBB"},
        {"uid": "5969072424", "password": "D28DD2F1BBADE23DA65A1619AA7227A239951BDADA9AF833C357E2BDA684CD2E"},
        {"uid": "5969072916", "password": "4427C79523D7E8EED381C993335CA7C98851C38605BF6B2F7B91F248A42D06FC"},
        {"uid": "6002492146", "password": "FB1587D45A91CC9BF754AE866199CAAE941E3E28525E347413BA0273164D6EB5"},
        {"uid": "6002506436", "password": "A358BCE10C643AC95AFBDA64F6217467438F4E0628A35082A1BA542094BECDC5"},
        {"uid": "6002518472", "password": "8D7CACB709CF67C8603031C8B8E7C617C414386C1376084454F9E5ADF2E6DECF"},
        {"uid": "6002520122", "password": "AD74E8F54907CA48B7D3FAD3906304F51F922D290F3A365BD52B066226ED44B9"},
        {"uid": "6002518744", "password": "78FBBE11132F956730A822D92929ACC2E4B8FCF65C0F2B3227A4A4924BE91DED"},
        {"uid": "6002526417", "password": "13CCDAD1348D0EFE6938A204FAED9D55C374D44850EED4C169543E94C59E94AD"},
        {"uid": "5969018111", "password": "A3AF7209810D14A27E0C63B638DC961488C46B51FD65CDC3C71C2ACD514A0741"},
        {"uid": "5969037910", "password": "537584E7FBAA137FCEFBB0DBEFC0C33C9119949EA3E8DCB8ED0983769B401DC9"},
        {"uid": "5969047463", "password": "4B81AAD74655745AE0B6DE5137181E4440317D6C25D372994ADFB4DCF2B8EFD0"},
        {"uid": "5969049772", "password": "C8449B2529F74F3D123733159CF17E2A23567B436ADB3612B87C17398A283651"},
        {"uid": "5969049870", "password": "CA142E507E6ED577BD976E89FBF475077AF6455CF938F3F12AF1305882351D06"},
        {"uid": "6002492143", "password": "E48BDFD72CFABEAFC37B3E04F5AC9B55564FC16046FF32D5639EB763072A09F1"},
        {"uid": "6002524721", "password": "05238FD206B1DA7C749006F9ED59162A1BAEB1AAA4A5DFDC00DF712C1AADBD80"},
        {"uid": "6002525156", "password": "1E058A6E4071B1D8907E210319B9E358AE6D54E24AC6A04843F18DA0C6FBEB98"},
        {"uid": "5969024961", "password": "C974C9B50437376F1B8D5A3500A3E3C4DA7F5100CC615F374720DA98D12C7F18"},
        {"uid": "5969045242", "password": "02D649EC9E4DB7C1F5E3509A17CBABE1467FDEE1F4C7756F43CE7398758B20B0"},
        {"uid": "6002505840", "password": "3CC03A60184BD39DC576E42AF678825C87B8AD0703287A6E1AA4D7FEA5C4F9DF"},
        {"uid": "6002511237", "password": "17FD8AD79B964485F32EF4CA7BEB4E052288044F742D33923A632FBE5AF462C1"},
        {"uid": "6002492136", "password": "B1DAC1A060287435E230095559F573C32C640C5ED4B5D6EEAA2376523B7B3801"},
        {"uid": "6002525502", "password": "C3DC542C2DFD8C1F7DA5CC8CA4583D0AE385276D99FF2502083D1B59DF0554BC"},
        {"uid": "5969038795", "password": "BB4034A1525C38306D91C00FC8A9F8C9D296CBE3A2F32A58EBD2F7C288443368"},
        {"uid": "6002512820", "password": "C593C05EA42662B46F2C12E216A1152D052DA3EEFF54BBC4579941D10493E9D5"},
        {"uid": "6002525563", "password": "8AE07CF27FB1F9B71649BC5ACA6F8864CE4F7D6BB250E94D66E423E643B62F21"},
        {"uid": "6002514554", "password": "9902F9F01A32ED6CDF7D48216175493E207232E426A0589835E2922FF6518286"},
    ],
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

# ---------------------------------------------------------------------------
# Per-account token cache + round-robin state
# ---------------------------------------------------------------------------
TOKEN_CACHE = {}                      # (pool, uid) -> token_info
ROUND_ROBIN = {p: 0 for p in ACCOUNTS}
ROUND_ROBIN_LOCK = threading.Lock()

# How many accounts to try per pool before giving up (raises cold-start latency)
MAX_ACCOUNT_TRIES_PER_POOL = 2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def resolve_pool(region):
    if not region:
        return "BD"
    return REGION_TO_POOL.get(region.upper().strip(), "BD")


def aes_encrypt(data):
    return AES.new(MAIN_KEY, AES.MODE_CBC, MAIN_IV).encrypt(pad(data, 16))


async def json_to_proto(json_data, proto_message):
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()


def pick_next_account(pool):
    """Atomically advance the pool's round-robin and return the next account."""
    accounts = ACCOUNTS.get(pool)
    if not accounts:
        return None
    with ROUND_ROBIN_LOCK:
        idx = ROUND_ROBIN[pool] % len(accounts)
        ROUND_ROBIN[pool] = (idx + 1) % len(accounts)
    return accounts[idx]


# ---- protobuf byte-walker helpers (unchanged) ----------------------------
def _rd_var(b, pos, end):
    v, sh = 0, 0
    while pos < end:
        x = b[pos]; pos += 1
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
            raw = b[pos:pos + ln]; pos += ln
            ok = False
            try:
                s = raw.decode("utf-8")
                if all(c.isprintable() or c in "\n\r\t" for c in s):
                    out.setdefault(f, []).append(s); ok = True
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
            out.setdefault(f, []).append(struct.unpack_from("<f", b, pos)[0]); pos += 4
        elif w == 1:
            out.setdefault(f, []).append(struct.unpack_from("<d", b, pos)[0]); pos += 8
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


# ---------------------------------------------------------------------------
# OAuth / MajorLogin / JWT generation
# ---------------------------------------------------------------------------
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


async def generate_jwt(pool, account):
    """Generate a fresh JWT for a single account."""
    oid, tok, plat, err = await _oauth(account["uid"], account["password"])
    if err:
        print(f"OAuth [{pool}/{account['uid']}]: {err}")
        return None
    if not oid or not tok:
        print(f"OAuth [{pool}/{account['uid']}]: no open_id/access_token")
        return None

    try:
        inf = await _inspect(tok)
    except Exception as e:
        print(f"Inspect [{pool}/{account['uid']}]: {e}")
        return None
    if "open_id" not in inf:
        print(f"Inspect [{pool}/{account['uid']}]: {inf}")
        return None

    oid = inf["open_id"]
    plat = str(inf.get("platform", plat or 4))

    login_url = LOGIN_HOSTS.get(pool, LOGIN_HOSTS["BD"])
    try:
        payload = build_login_payload(oid, tok, plat, JWT_CV)
        resp = await majorlogin(payload, JWT_RLS, login_url)
    except Exception as e:
        print(f"MajorLogin [{pool}/{account['uid']}]: {e}")
        return None

    parsed = parse_majorlogin(resp.content)
    jwt = parsed.get("jwt")
    if not jwt:
        print(f"No JWT [{pool}/{account['uid']}]")
        return None

    server_url = parsed.get("server_url")
    if not server_url:
        print(f"No server_url [{pool}/{account['uid']}]")
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

    print(f"JWT ready [pool={pool} uid={account['uid']}] -> {real_region} @ {server_url}")

    return {
        "token": f"Bearer {jwt}",
        "pool": pool,
        "account_uid": account["uid"],
        "token_region": real_region,
        "server_url": server_url,
        "expires_at": time.time() + JWT_TTL,
        "cache_key": (pool, account["uid"]),
    }


async def get_token(pool, force=False):
    """
    Pick next account in the pool via round-robin.
    Reuse cached JWT if still valid (7h TTL); otherwise generate a fresh one.
    On generation failure, try up to MAX_ACCOUNT_TRIES_PER_POOL accounts.
    """
    accounts = ACCOUNTS.get(pool)
    if not accounts:
        return None

    for _ in range(MAX_ACCOUNT_TRIES_PER_POOL):
        account = pick_next_account(pool)
        if account is None:
            return None

        key = (pool, account["uid"])
        cached = TOKEN_CACHE.get(key)
        if not force and cached and cached.get("expires_at", 0) > time.time() + 60:
            return cached

        info = await generate_jwt(pool, account)
        if info:
            TOKEN_CACHE[key] = info
            return info
    return None


# ---------------------------------------------------------------------------
# GetPlayerPersonalShow
# ---------------------------------------------------------------------------
def is_valid_response(data):
    if not isinstance(data, dict):
        return False
    bi = data.get("basicInfo")
    if not isinstance(bi, dict):
        return False
    return bool(bi.get("nickname"))


async def get_player_info(uid, pool):
    token_info = await get_token(pool)
    if not token_info:
        return None

    server_url = token_info["server_url"]
    token = token_info["token"]

    try:
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

        if r.status_code == 401:
            # Token rejected — drop it so the next pick regenerates.
            TOKEN_CACHE.pop(token_info.get("cache_key"), None)
            print(f"401 [{pool}/{token_info['account_uid']}] — dropping token")
            return None

        if r.status_code != 200:
            print(f"GetPlayerPersonalShow [{pool}/{token_info['account_uid']}] {url} -> {r.status_code}")
            return None

        info = AccountPersonalShow_pb2.AccountPersonalShowInfo()
        info.ParseFromString(r.content)
        return json.loads(json_format.MessageToJson(info))
    except Exception as e:
        print(f"get_player_info[{pool}/{token_info['account_uid']}]: {e}")
        return None


async def try_pool(uid, pool, max_attempts=None):
    """
    Try up to `max_attempts` distinct accounts within one pool.
    - error / None  -> retry with next account
    - 200 but empty -> player is NOT in this region -> stop retrying (save JWTs)
    - valid data    -> return
    """
    if max_attempts is None:
        max_attempts = MAX_ACCOUNT_TRIES_PER_POOL

    for _ in range(max_attempts):
        data = await get_player_info(uid, pool)
        if data is None:
            continue  # transient/account error — rotate and retry
        if is_valid_response(data):
            return data
        # Got a well-formed 200 with no nickname → player really isn't here.
        return None
    return None


# ---------------------------------------------------------------------------
# Response reshaping
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    return jsonify({
        "status": "running",
        "version": JWT_RLS,
        "endpoint": "/info?uid=UID[&region=REGION]",
        "auto_search_order": SEARCH_ORDER,
        "accounts_per_pool": {p: len(a) for p, a in ACCOUNTS.items()},
        "rotation": "round-robin per pool",
        "cache": f"per-account, {JWT_TTL // 3600}h TTL",
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
                data = await try_pool(uid_int, pool)
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
    out = {}
    for pool in ACCOUNTS:
        tokens = []
        for (p, uid), info in TOKEN_CACHE.items():
            if p != pool:
                continue
            tokens.append({
                "account_uid": uid,
                "token_region": info["token_region"],
                "server_url": info["server_url"],
                "expires_in_hours": round((info["expires_at"] - now) / 3600, 2),
            })
        out[pool] = {
            "total_accounts": len(ACCOUNTS[pool]),
            "cached_tokens": len(tokens),
            "tokens": tokens,
        }
    return jsonify(out)


@app.route("/refresh")
def refresh():
    """Clear cache and pre-warm one token per pool (parallel)."""
    TOKEN_CACHE.clear()

    async def run():
        await asyncio.gather(
            *(get_token(p, force=True) for p in SEARCH_ORDER),
            return_exceptions=True,
        )

    try:
        asyncio.run(run())
        return jsonify({
            "status": "refreshed",
            "cached": [f"{p}:{u}" for (p, u) in TOKEN_CACHE.keys()],
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5004, debug=False)
