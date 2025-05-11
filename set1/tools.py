import codecs
import math

def decode_hex(s: str):
  return codecs.decode(s, 'hex')

def encode_hex(s: bytes):
  return codecs.encode(s, 'hex')

def encode_base64(bs: bytes):
  b64 = codecs.encode(bs, 'base64').decode()
  return b64.replace("\n", "")

def decode_base64(s: str):
  b64 = s.encode('utf-8')
  return codecs.decode(b64, 'base64')

def xor_buffers(a: bytes, b: bytes):
  if len(a) > len(b):
    raise ValueError("Second buffer must be as long as first")

  return bytes([a[i] ^ b[i] for i in range(len(a))])

def xor_repeating_key(ptxt: bytes, key: bytes):
	mask = key * math.ceil(len(ptxt) / len(key))
	return xor_buffers(ptxt, mask)