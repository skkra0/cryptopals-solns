from Crypto.Cipher import AES
import secrets
from soln_8 import is_ecb
from tools import decode_base64, pad

class Oracle:
    """
    Oracle that encrypts plaintexts under AES-ECB with a random key, after
    prepending random bytes and appending a target string. The key and the prefix
    are generated at initialization. The prefix is shorter than a block.
    """
    def __init__(self, keysize: int):
        self.blocksize = keysize
        self.key = secrets.token_bytes(keysize)
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        prefix_size = secrets.randbelow(2 * keysize)
        self.prefix = secrets.token_bytes(prefix_size)
        self.suffix = decode_base64(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
            "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
            "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"  
            "YnkK"
        )

    def enc(self, ptxt: bytes):
        """
        Encrypts a plaintext after placing it in between the generated
        prefix and the target suffix.
        """
        full_ptxt = self.prefix + ptxt + self.suffix
        full_ptxt = pad(full_ptxt, self.blocksize)
        return self.cipher.encrypt(full_ptxt)

def get_lengths(oracle: Oracle):
    """
    Find block size by encrypting increasingly large strings. Compare ciphertexts
    to find the block where the prefix ends and our input starts. Then encrypt
    increasingly large strings until our input makes up two identical blocks of
    ciphertext to find the prefix length. Subtract to find the length of the target.
    """
    test_str = b""
    base_size = len(oracle.enc(test_str))
    next_size = base_size
    while next_size == base_size:
        test_str += b"A"
        next_size = len(oracle.enc(test_str))
    blocksize = next_size - base_size

    ctxt_1 = oracle.enc(b"")
    ctxt_2 = oracle.enc(b"A")

    input_start_block = -1
    for i in range(0, len(ctxt_2), blocksize):
        if ctxt_1[i: i + blocksize] != ctxt_2[i: i + blocksize]:
            input_start_block = i
            break
    
    prefix_length = -1
    for i in range(blocksize + 1):
        fill = bytearray(b"A" * (2 * blocksize + i))
        ctxt = oracle.enc(fill)
        block1_start =  input_start_block + blocksize
        block1 = ctxt[block1_start: block1_start + blocksize]
        block2 = ctxt[block1_start + blocksize: block1_start + 2 * blocksize]
        if block1 == block2:
            prefix_length = block1_start - i
            break
    target_length = next_size - prefix_length - len(test_str) - blocksize
    return prefix_length, target_length, blocksize
    
def create_dictionary_at(oracle: Oracle, blocksize: int, prefix_length: int, target_idx: int, known_target_prefix: bytes):
    """
    Given the known target plaintext up to a certain index, encrypts blocks containing
    the known plaintext followed by a possible byte to return a dictionary from
    blocks of ciphertext to the final byte used.
    """
    bdict = {}
    prefix_fill = b"A" * (blocksize - prefix_length % blocksize)
    known_pad = b"A" * (blocksize - target_idx % blocksize - 1)
    known_fill = bytearray(prefix_fill + known_pad + known_target_prefix)
    known_start = prefix_length + len(prefix_fill)
    block_start = known_start + (target_idx // blocksize) * blocksize
    for c in range(256):
        known_fill.append(c)
        ctxt = oracle.enc(known_fill)
        block = ctxt[block_start: block_start + blocksize]
        bdict[block] = c
        known_fill.pop()
    return bdict

def decrypt_target(oracle):
    """
    Returns the plaintext string that the oracle appends to the end of messages.
    Decrypts a byte at a time by aligning it at the end of a block and looking up the
    block of ciphertext in a dictionary between ciphertexts and known last bytes.
    """
    prefix_length, suffix_length, blocksize = get_lengths(oracle)

    if not is_ecb(oracle.enc(bytes(3 * blocksize))):
        raise ValueError("Not ECB!")

    target = bytearray()
    prefix_fill = b"A" * (blocksize - prefix_length % blocksize)
    known_start = prefix_length + len(prefix_fill)
    for i in range(suffix_length):
        bdict = create_dictionary_at(oracle, blocksize, prefix_length, i, bytes(target))
        known_fill = prefix_fill + b"A" * (blocksize - i % blocksize - 1)
        block_start = known_start + (i // blocksize) * blocksize
        ctxt = oracle.enc(known_fill)
        block = ctxt[block_start: block_start + blocksize]
        target.append(bdict[block])
    
    return bytes(target)
if __name__ == "__main__":
    oracle = Oracle(16)
    res = decrypt_target(oracle)
    assert(res == decode_base64(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"  
        "YnkK"
    ))
    print(res)