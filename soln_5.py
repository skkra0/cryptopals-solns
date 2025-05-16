from tools import xor_buffers, encode_hex
import math
def xor_repeating_key(ptxt: bytes, key: bytes):
    """XORs a message with a repeating key."""
    mask = key * math.ceil(len(ptxt) / len(key))
    return xor_buffers(ptxt, mask)

if __name__ == "__main__":
    pt = bytes(
        "Burning 'em, if you ain't quick and nimble\n"
        "I go crazy when I hear a cymbal"
    , "utf-8")
    res = xor_repeating_key(pt, b"ICE")

    assert(encode_hex(res).decode("utf-8") == (
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
        "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    ))