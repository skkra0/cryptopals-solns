from soln_10 import enc_cbc
from soln_8 import is_ecb
from Crypto.Cipher import AES
import secrets
from tools import decode_base64, pad

def enc_random(ptxt: bytes, keysize: bytes = 16):
    """
    Adds 5-10 random bytes before and after a plaintext and randomly
    encrypts the result with either AES-ECB or AES-CBC. If CBC is chosen,
    a random initialization vector is used.
    """
    key = secrets.token_bytes(keysize)

    append_head = 5 + secrets.randbelow(6)
    append_tail = 5 + secrets.randbelow(6)
    ptxt = secrets.token_bytes(append_head) + ptxt + secrets.token_bytes(append_tail)
    ptxt = pad(ptxt, keysize)

    if secrets.randbelow(2) == 0:
        cipher = AES.new(key, AES.MODE_ECB)
        return "ecb", cipher.encrypt(ptxt)
    else:
        return "cbc", enc_cbc(ptxt, key, secrets.token_bytes(keysize))

if __name__ == "__main__":
    blocksize = 16
    ptxt = bytes(blocksize * 3)
    for _ in range(100):
        method, ctxt = enc_random(ptxt)
        if is_ecb(ctxt):
            assert(method == "ecb")
        else:
            assert(method == "cbc")
    
    print("Detected correctly x100")