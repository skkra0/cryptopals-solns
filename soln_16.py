from Crypto.Cipher import AES
import secrets
from tools import xor_buffers, pad
class Oracle:
    """
    Encrypts plaintexts under AES-128-CBC under a random key and IV, with fixed
    prefix and suffix.
    """
    def __init__(self):
        key = secrets.token_bytes(16)
        self.enc_cipher = AES.new(key, AES.MODE_CBC)
        self.prefix = b"comment1=cooking%20MCs;userdata="
        self.suffix = b";comment2=%20like%20a%20pound%20of%20bacon"
        self.dec_cipher = AES.new(key, AES.MODE_CBC, self.enc_cipher.iv)

    def enc(self, ptxt: str):
        """
        Encrypts a plaintext after adding prefix and suffix, 
        URL-encoding metacharacters ; and =.
        """
        ptxt = ptxt.replace(";", "%27").replace("=", "%3D")
        full_ptxt = self.prefix + ptxt.encode("utf-8") + self.suffix
        return self.enc_cipher.encrypt(pad(full_ptxt, 16))

    def is_admin(self, ctxt: bytes):
        """Decrypts the given ciphertext and checks if it is admin."""
        ptxt_padded = self.dec_cipher.decrypt(ctxt)
        padding_amount = ptxt_padded[-1]
        ptxt = ptxt_padded[:-padding_amount]
        return b";admin=true;" in ptxt

def build_admin_ctxt(oracle: Oracle):
    """
    Builds a ciphertext of a message containing ;admin=true; by
    XORing the previous block with the difference between normal
    and admin plaintexts. Assumes block size and start position of
    input are known.
    """

    normal = "nothing to see here this is good" # 32 characters
    malicious = "abcde;admin=true" # 16 characters

    base_ctxt = oracle.enc(normal)
    diff = xor_buffers(normal[16:].encode("utf-8"), malicious.encode("utf-8"))
    
    modified_block = xor_buffers(base_ctxt[32:48], diff)
    return base_ctxt[:32] + modified_block + base_ctxt[48:]

if __name__ == "__main__":
    oracle = Oracle()
    
    admin = build_admin_ctxt(oracle)
    assert(oracle.is_admin(admin))