from tools import decode_hex

def is_ecb(ctxt: bytes, blocksize: int = 16):
    """
    Guesses if a ciphertext was encrypted with AES in ECB mode
    by checking for repeated blocks. The same plaintext block
    always produces the same ciphertext block under ECB.
    """
    blocks = []
    for i in range(0, len(ctxt), blocksize):
        block = ctxt[i:i + blocksize]
        if block in blocks:
            return True
        blocks.append(block)
    return False

if __name__ == "__main__":
    with open('data/8.txt', 'r') as f:
        for idx, line in enumerate(f.read().splitlines()):
            ctxt = decode_hex(line)
            if is_ecb(ctxt):
                print(f"Possible ECB at line {idx}")