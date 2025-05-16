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
        prefix_size = secrets.randbelow(keysize)
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

def get_padding_block(oracle: Oracle):
    """
    Encrypts increasingly large strings until an additional block
    of padding is appended to the ciphertext. Then, returns the
    encrypted block of padding.
    """
    test_str = b""
    ctxt = oracle.enc(test_str)
    last_size = len(ctxt)
    next_size = last_size
    while next_size == last_size:
        test_str += b"A"
        ctxt = oracle.enc(test_str)
        next_size = len(ctxt)
    block_size = next_size - last_size
    return ctxt[-block_size:]

def get_lengths(oracle: Oracle):
    """
    Finds the size of the prefix by encrypting an increasingly large string
    of padding bytes until the last block containing the prefix has been "filled"
    and a block of padding can be found before the end of the ciphertext. Then,
    finds the size of the appended target string by adding bytes until a block
    of padding is added to the end of the ciphertext. Assumes that a block of
    padding bytes does not exist in the prefix or the suffix.
    """
    padding_block = get_padding_block(oracle)
    block_size = len(padding_block)
    test_str = b"\x10" * block_size
    ctxt = oracle.enc(test_str)
    msg_idx = ctxt.find(padding_block)
    while msg_idx == -1 or msg_idx == len(ctxt) - block_size:
        test_str += b"\x10"
        ctxt = oracle.enc(test_str)
        msg_idx = ctxt.find(padding_block)
    prefix_fill = len(test_str) - block_size
    prefix_length = msg_idx - prefix_fill

    padding_idx = ctxt.find(padding_block, msg_idx + block_size)
    while padding_idx == -1:
        test_str += b"\x10"
        ctxt = oracle.enc(test_str)
        padding_idx = ctxt.find(padding_block, msg_idx + block_size)
    suffix_fill = len(test_str) - block_size - prefix_fill
    suffix_length = len(ctxt) - msg_idx - 2 * block_size - suffix_fill
    return prefix_length, suffix_length, block_size

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