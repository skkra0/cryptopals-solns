from tools import decode_base64
from Crypto.Cipher import AES

if __name__ == "__main__":
    key = b'YELLOW SUBMARINE'

    with open('data/7.txt', 'r') as f:
        ctxt = decode_base64(f.read())

        cipher = AES.new(key, AES.MODE_ECB)
        ptxt = cipher.decrypt(ctxt)
        print(ptxt)