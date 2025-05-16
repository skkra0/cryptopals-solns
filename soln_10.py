from tools import decode_base64, xor_buffers
from Crypto.Cipher import AES

def enc_cbc(ptxt: bytes, key: bytes, iv: bytes):
    """Encrypts a given plaintext under AES-CBC, given a key and IV."""
    if len(ptxt) % len(key) != 0:
        raise ValueError("Padding")
    
    if len(iv) != len(key):
        raise ValueError("Incorrect sized initialization vector")

    cipher = AES.new(key, AES.MODE_ECB)
    ctxt = bytearray()
    last_ctxt = iv

    blocksize = len(key)
    for i in range(0, len(ptxt), blocksize):
        block = xor_buffers(last_ctxt, ptxt[i: i + blocksize])
        last_ctxt = cipher.encrypt(block)
        ctxt += last_ctxt
    
    return bytes(ctxt)

def dec_cbc(ctxt: bytes, key: bytes, iv: bytes):
    """Decrypts a given plaintext under AES-CBC, given a key and IV."""
    if len(ctxt) % len(key) != 0:
        raise ValueError("Padding")
    
    if len(iv) != len(key):
        raise ValueError("Incorrect sized initialization vector")

    cipher = AES.new(key, AES.MODE_ECB)
    ptxt = bytearray()
    last_ctxt = iv
    for i in range(0, len(ctxt), len(key)):
        last_ctxt_block = ctxt[i: i + len(key)]
        ptxt += xor_buffers(cipher.decrypt(last_ctxt_block), last_ctxt)
        last_ctxt = last_ctxt_block
    return bytes(ptxt)

if __name__ == "__main__":
    with open("data/10.txt", "r") as f:
        ctxt = decode_base64(f.read())
    
        ptxt = dec_cbc(ctxt, b"YELLOW SUBMARINE", bytes([0] * 16))
        assert(ctxt == enc_cbc(ptxt, b"YELLOW SUBMARINE", bytes([0] * 16)))
        print(ptxt)