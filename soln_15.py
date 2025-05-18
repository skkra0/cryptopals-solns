from tools import validate_padding

if __name__ == "__main__":
    assert(validate_padding(b"ICE ICE BABY\x04\x04\x04\x04") is True)
    assert(validate_padding(b"ICE ICE BABY\x05\x05\x05\x05") is False)
    assert(validate_padding(b"ICE ICE BABY\x01\x02\x03\x04") is False)