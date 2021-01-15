import re
import uuid
import requests
import rsa
import lzstring
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from bs4 import BeautifulSoup
import json

def encrypt(key_str, uid, upw):
    def naver_style_join(l):
        return "".join([chr(len(s)) + s for s in l])

    sessionkey, keyname, e_str, n_str = key_str.split(',')
    e, n = int(e_str, 16), int(n_str, 16)

    message = naver_style_join([sessionkey, uid, upw]).encode()

    pubkey = rsa.PublicKey(e, n)
    encrypted = rsa.encrypt(message, pubkey)

    return keyname, encrypted.hex()

def encrypt_account(uid, upw):
    key_str = requests.get('https://nid.naver.com/login/ext/keys2.nhn').content.decode('utf-8')
    return encrypt(key_str, uid, upw)

def naver_session(nid, upw):
    encnm, encpw = encrypt_account(nid, upw)

    s = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=0.1,
        status_forcelist=[500, 502, 503, 504]
    )

    s.mount('https://', HTTPAdapter(max_retries=retries))
    request_headers = {
        'User-Agent': 'Mozilla/5.0'
    }

    bvsd_uuid = uuid.uuid4()
    encData = '{"a":"%s-4","b":"1.3.4","d":[{"i":"id","b":{"a":["0,%s"]},"d":"%s","e":false,"f":false},{"i":"%s","e":true,"f":false}],"h":"1f","i":{"a":"Mozilla/5.0"}}' % (
        bvsd_uuid, nid, nid, upw
    )
    bvsd = '{"uuid":"%s","encData":"%s"}' % (bvsd_uuid, lzstring.LZString.compressToEncodedURIComponent(encData))

    resp = s.post('https://nid.naver.com/nidlogin.login', data={
        'enctp': '1',
        'svctype': '1',
        'locale': 'ko_KR',
        'encnm': encnm,
        'url': 'https://www.naver.com',
        'smart_LEVEL': '1',
        'encpw': encpw,
        'bvsd': bvsd,
        'id': nid,
        'pw': upw
    }, headers=request_headers)
    print(resp.content)

    finalize_url = re.search(r'location\.replace\("([^"]+)"\)', resp.content.decode("utf-8")).group(1)
    s.get(finalize_url)

    return s

def get_id_pwd(filename):
    id = ''
    pw = ''

    with open(filename, encoding='utf-8') as f:
        json_data = json.load(f)
        id = json_data['id']
        pw = json_data['pwd']

    return id, pw


if __name__ == '__main__':
    id, pw = get_id_pwd('id_pw.json')
    s = naver_session(id, pw)
    pp = s.get('https://mail.naver.com/').content.decode('utf-8')
    soup = BeautifulSoup(pp, 'lxml')
    print(soup)