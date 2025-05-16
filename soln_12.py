from Crypto.Cipher import AES
from secrets import token_bytes
from soln_8 import is_ecb
from tools import decode_base64, pad

class Oracle:
    """
    Oracle that encrypts plaintexts under AES-ECB with a key generated at
    initialization, after appending a fixed string.
    """
    def __init__(self, keysize: int = 16):
        self.blocksize = keysize
        key = token_bytes(keysize)
        self.cipher = AES.new(key, AES.MODE_ECB)
        self.suffix = decode_base64(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
            "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
            "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"  
            "YnkK"
        )

    def enc(self, ptxt: bytes):
        """Appends a string to plaintext, adds PKCS#7 padding, and encrypts it."""
        full_ptxt = ptxt + self.suffix
        full_ptxt = pad(full_ptxt, self.blocksize)
        return self.cipher.encrypt(full_ptxt)

def get_sizes(oracle: Oracle):
    """
    Find block size and target size by encrypting increasingly large strings.
    When the ciphertext increases in size, it is because a block of padding
    was appended, indicating the block size as well as the size of the message
    without any padding.
    """
    test_str = b""
    last_size = len(oracle.enc(test_str))
    next_size = last_size
    while next_size == last_size:
        test_str += b"A"
        next_size = len(oracle.enc(test_str))
    blocksize = next_size - last_size
    unknown_size = last_size - len(test_str)
    return unknown_size, blocksize

def create_dictionary_at(oracle: Oracle, blocksize: int, idx: int, known_ptxt_prefix: bytes):
    """
    Given the known target plaintext up to a certain index, encrypts blocks containing
    the known plaintext followed by a possible byte to return a dictionary from
    blocks of ciphertext to the final byte used.
    """
    bdict = {}
    known_pad = b"A" * (blocksize - (idx % blocksize) - 1)
    known_prefix = bytearray(known_pad)
    known_prefix += known_ptxt_prefix
    for c in range(256):
        known_prefix.append(c)
        ctxt = oracle.enc(known_prefix)
        block_start = (idx // blocksize) * blocksize
        block = ctxt[block_start: block_start + blocksize]
        bdict[block] = c
        known_prefix.pop()
    return bdict

def decrypt_target(oracle: Oracle):
    """
    Returns the plaintext string that the oracle appends to the end of messages.
    Decrypts a byte at a time by aligning it at the end of a block and looking up the
    block of ciphertext in a dictionary between ciphertexts and known last bytes.
    """
    target_size, blocksize = get_sizes(oracle)
    if not is_ecb(oracle.enc(bytes(2 * blocksize))):
        raise ValueError("Not ECB!")
    
    ptxt = bytearray()
    for i in range(target_size):
        bdict = create_dictionary_at(oracle, blocksize, i, bytes(ptxt))
        block_start = (i // blocksize) * blocksize
        prefix = b"A" * (blocksize - (i % blocksize) - 1)
        ctxt = oracle.enc(prefix)
        block = ctxt[block_start:block_start + 16]
        ptxt.append(bdict[block])
    return bytes(ptxt)

if __name__ == "__main__":
    oracle = Oracle()
    ptxt = decrypt_target(oracle)
    assert(ptxt == decode_base64(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"  
        "YnkK"
    ))
    print(ptxt)
