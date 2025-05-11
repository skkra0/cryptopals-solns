from tools import decode_hex

def has_repeated_block(ctxt: bytes):
    blocks = []
    for i in range(0, len(ctxt), 16):
        block = ctxt[i:i + 16]
        if block in blocks:
            return True
        blocks.append(block)
    return False

if __name__ == "__main__":
    with open('data/8.txt', 'r') as f:
        for idx, line in enumerate(f.read().splitlines()):
            ctxt = decode_hex(line)
            if has_repeated_block(ctxt):
                print(ctxt)
                print(f"Possible ECB at line {idx}")