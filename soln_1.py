from tools import decode_hex, encode_base64

def soln(hex: str):
    return encode_base64(decode_hex(hex))

if __name__ == "__main__":
    res = soln("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    assert(res == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")