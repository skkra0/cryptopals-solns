from tools import pad

if __name__ == "__main__":
    assert(pad(b"YELLOW SUBMARINE", 20) == b"YELLOW SUBMARINE\x04\x04\x04\x04")