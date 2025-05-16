from tools import decode_hex, encode_hex, xor_buffers

def soln(a: str, b: str):
    a_buf = decode_hex(a)
    b_buf = decode_hex(b)
    raw = xor_buffers(a_buf, b_buf)
    return encode_hex(raw).encode("utf-8")

if __name__ == "__main__":
    res = soln("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
    assert(res == "746865206b696420646f6e277420706c6179")