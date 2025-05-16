from Crypto.Cipher import AES
from secrets import token_bytes
from tools import pad

class Oracle:
    """
    Creates and encrypts profiles made up of three key-value pairs:
    email, uid, and role.
    """
    def __init__(self, keysize: int = 16):
        self.blocksize = keysize
        self.key = token_bytes(keysize)
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        self.uid = 0

    def profile_for(self, email: str):
        """
        Given an email, creates a profile encoded as key=value pairs,
        removing metacharacters & and =.
        """
        self.uid += 1
        email = email.replace("&", "").replace("=", "")
        return f"email={email}&uid={self.uid}&role=user"
    
    def enc_profile(self, email: str):
        """Given an email, creates a profile and encrypts it."""
        profile = self.profile_for(email)
        full_ptxt = pad(profile.encode('utf-8'), self.blocksize)
        return self.cipher.encrypt(full_ptxt)

    def dec_profile(self, ctxt: bytes):
        """Decrypts a profile to a key-value string, removing padding."""
        ptxt = self.cipher.decrypt(ctxt)
        padding = ptxt[-1]
        return ptxt[:-padding].decode("utf-8")

def parse_key_value(pairs: str):
    """Parses key-value string to a dictionary."""
    tokens = pairs.split("&")
    vals = {}
    try:
        for t in tokens:
            key, val = t.split('=')
            vals[key] = val
    except:
        raise ValueError("Invalid key=value")
    return vals

def get_block_size():
    """
    Find block size by encrypting increasingly large strings. Since the plaintext
    is growing by less than the block size at a time, when the ciphertext gets larger,
    it is because a block of padding was appended, indicating the block size.
    Uses a new oracle object for each test string to avoid increasing the UID length.
    """
    oracle = Oracle()
    test_str = ""
    last_size = len(oracle.enc_profile(test_str))
    next_size = last_size
    while next_size == last_size:
        test_str += "A"
        next_size = len(oracle.enc_profile(test_str))
    blocksize = next_size - last_size
    return blocksize

def build_enc_admin_profile(oracle: Oracle):
    """
    Builds an encrypted profile with the role set to "admin" by
    encrypting a block starting with "admin" and pasting it into
    a profile in which the value of the role starts at a new block.
    Assumes that ciphertexts contain profiles that look like
    email={input}&uid=x&role=
    """
    blocksize = get_block_size()
    padding_size = blocksize - len("admin")

    admin_ptxt = b"A" * (blocksize - len("email=")) + b"admin" + bytes([padding_size] * padding_size)
    admin_block_profile = oracle.enc_profile(admin_ptxt.decode("utf-8"))
    admin_block = admin_block_profile[blocksize: blocksize * 2]

    known_profile_text = "email=admin@admin.com&uid=x&role="
    admin_email = "a" * (blocksize - len(known_profile_text) % blocksize) + "admin@admin.com"
    normal_enc_profile = oracle.enc_profile(admin_email)

    return normal_enc_profile[:-16] + admin_block

if __name__ == "__main__":
    oracle = Oracle()
    enc_profile = build_enc_admin_profile(oracle)
    profile = parse_key_value(oracle.dec_profile(enc_profile))
    assert(profile["role"] == "admin")
    print(profile)