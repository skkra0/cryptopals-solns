from three import break_single_char_xor, xor_repeating_key
from tools import decode_base64

def hamming_distance(a: bytes, b: bytes):
    if len(a) != len(b):
        raise ValueError("Strings must be of the same length")
    
    return sum(bin(x).count("1") for x in [a[i] ^ b[i] for i in range(len(a))])


def break_repeating_key_xor(ctxt: bytes):
    size_to_distance = {}
    for keysize in range(2, 41):
        first_four_blocks = [ctxt[i: i + keysize] for i in range(0, 4 * keysize, keysize)]
        if len(first_four_blocks[3]) != keysize:
            break
        distance = (
                    hamming_distance(first_four_blocks[0], first_four_blocks[1]) +
                    hamming_distance(first_four_blocks[1], first_four_blocks[2]) +
                    hamming_distance(first_four_blocks[2], first_four_blocks[3]) +
                    hamming_distance(first_four_blocks[0], first_four_blocks[2]) +
                    hamming_distance(first_four_blocks[0], first_four_blocks[3]) +
                    hamming_distance(first_four_blocks[1], first_four_blocks[3])
                    ) / 6
        size_to_distance[keysize] = distance / keysize
    
    keysize = min(size_to_distance, key=size_to_distance.get)
    blocks = [ctxt[i: i + keysize] for i in range(0, len(ctxt), keysize)]
    blocks_transposed = []
    for i in range(keysize):
        block = bytearray()
        for j in range(len(blocks)):
            if i < len(blocks[j]):
                block.append(blocks[j][i])
        blocks_transposed.append(bytes(block))
    
    key = bytearray()
    for bt in blocks_transposed:
        best_plaintext, best_key, _, _ = break_single_char_xor(bt)
        key += best_key
    key = bytes(key)
    return (key, xor_repeating_key(ctxt, key))

if __name__ == "__main__":
    with open('data/6.txt', 'r') as f:
        ctxt = decode_base64(f.read())
        print(break_repeating_key_xor(ctxt))