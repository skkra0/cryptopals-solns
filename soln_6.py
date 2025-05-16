from soln_3 import break_single_char_xor
from soln_5 import xor_repeating_key
from tools import decode_base64, xor_buffers

def hamming_distance(a: bytes, b: bytes):
    """Get the number of differing bits between two strings"""
    if len(a) != len(b):
        raise ValueError("Strings must be of the same length")
    
    return sum(bin(x).count("1") for x in xor_buffers(a, b))

def get_keysize(ctxt: bytes):
    """
    Guess the size of the repeating key the message was XOR'd with by
    taking the average normalized edit distance between the first four
    blocks, and returning the key size that produced the lowest distance.
    """
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
    
    return min(size_to_distance, key=size_to_distance.get)

def break_repeating_key_xor(ctxt: bytes):
    """
    Breaks repeating-key XOR by breaking ciphertext into blocks of
    the guessed size, transposing, then solving as single-character XOR
    to recover the key. Returns key and plaintext.
    """
    keysize = get_keysize(ctxt)
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
        key.append(best_key)
    key = bytes(key)
    return key, xor_repeating_key(ctxt, key)

if __name__ == "__main__":
    assert(hamming_distance(b"this is a test", b"wokka wokka!!!") == 37)

    with open('data/6.txt', 'r') as f:
        ctxt = decode_base64(f.read())
    print(break_repeating_key_xor(ctxt))