import codecs
import math

def decode_hex(s: str):
  """Decodes a hex string to bytes."""
  return codecs.decode(s, 'hex')

def encode_hex(s: bytes):
  """Encodes bytes as a hex string."""
  return codecs.encode(s, 'hex')

def encode_base64(bs: bytes):
  """Encodes bytes to base64."""
  b64 = codecs.encode(bs, 'base64').decode()
  return b64.replace("\n", "")

def decode_base64(s: str):
  """Decodes base64 to bytes."""
  b64 = s.encode('utf-8')
  return codecs.decode(b64, 'base64')

def xor_buffers(a: bytes, b: bytes):
  """XORs two byte strings with each other."""
  if len(a) > len(b):
    raise ValueError("Second buffer must be as long as first")

  return bytes([a[i] ^ b[i] for i in range(len(a))])

def pad(msg: bytes, blocksize: int):
  """Appends PKCS#7 padding to a message for a given block size."""
  if len(msg) % blocksize == 0:
      return msg + bytes([blocksize] * blocksize)
  diff = blocksize - len(msg) % blocksize
  return msg + bytes([diff] * diff)

def validate_padding(msg: bytes):
  """Tests if the data is PKCS#7 padded."""
  if not msg:
    return False
  expected_padding_amount = msg[-1]
  if expected_padding_amount > len(msg):
    return False
  for i in range(len(msg) - 1, len(msg) - expected_padding_amount - 1, -1):
    if msg[i] != expected_padding_amount:
      return False
  return True