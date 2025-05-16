from collections import defaultdict
import string
import math
from tools import decode_hex, xor_buffers

printable_characters = set(string.printable)
letter_freq = {
    'e': 0.1249,
    't': 0.0928,
    'a': 0.0804,
    'o': 0.0764,
    'i': 0.0757,
    'n': 0.0723,
    's': 0.0651,
    'r': 0.0628,
    'h': 0.0505,
    'l': 0.0407,
    'd': 0.0382,
    'c': 0.0334,
    'u': 0.0273,
    'm': 0.0251,
    'f': 0.0240,
    'p': 0.0214,
    'g': 0.0187,
    'w': 0.0168,
    'y': 0.0166,
    'b': 0.0148,
    'v': 0.0105,
    'k': 0.0054,
    'x': 0.0023,
    'j': 0.0016,
    'q': 0.0012,
    'z': 0.0009,
}

def get_char_frequencies(ptxt: bytes):
	"""
	Returns the frequencies of characters in a given plaintext
	out of 1. Uppercase letters are counted with lowercase.
	"""
	freq_map = defaultdict(int)
	for c in string.ascii_lowercase:
		freq_map[ord(c)] = 0
	for c in ptxt:
		if chr(c).isupper():
			freq_map[c + ord('a') - ord('A')] += 1
		else:
			freq_map[c] += 1
	for c in freq_map:
		freq_map[c] /= len(ptxt)
	return freq_map

def get_plaintext_score(ptxt_freq: dict):
	"""
	Returns the Bhattacharyya distance between the letter frequency
	distributions of the English language and a given plaintext.
	"""
	coeff = 0
	for char in letter_freq:
		coeff += math.sqrt(ptxt_freq[ord(char)] * letter_freq[char])
	if coeff == 0:
		return float('inf')
	return -1 * math.log(coeff)

def count_unprintable(ptxt_freq: bytes):
	"""Counts unprintable characters in a byte string."""
	total = 0
	for c in ptxt_freq:
		if chr(c) not in printable_characters:
			total += ptxt_freq[c]
	return total

def break_single_char_xor(ctxt: bytes):
	"""
	Given that the ciphertext was XOR'd against a single character,
	generates every possible plaintext, scores its similarity to
	English text, and returns the plaintext with the best score.
	Breaks ties based on lowest number of unprintable characters.
	"""
	best_plaintext = None
	best_score = float('inf')
	best_unprintable = float('inf')
	best_key = None
	msg_len = len(ctxt)
	for i in range(256):
		key = bytes([i] * msg_len)
		ptxt = xor_buffers(ctxt, key)
		ptxt_freq = get_char_frequencies(ptxt)
		score = get_plaintext_score(ptxt_freq)
		unprintable = count_unprintable(ptxt_freq)
		if score < best_score or (score == best_score and unprintable < best_unprintable):
			best_plaintext = ptxt
			best_score = score
			best_unprintable = unprintable
			best_key = i
	return best_plaintext, best_key, best_score, best_unprintable

if __name__ == "__main__":
	ctxt = decode_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	print(break_single_char_xor(ctxt))