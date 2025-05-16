from tools import decode_hex
from soln_3 import break_single_char_xor
def find_ctxt(cands: list[str]):
	"""
	Given a list of hex strings, finds the one most likely to be
	English text XOR'd with a single character and returns its
	index, plaintext, and key.
	"""
	best_score = float('inf')
	best_unprintable = float('inf')
	best_key = None
	best_ptxt = None
	best_idx = -1

	for idx, line in enumerate(cands):
		ctxt = decode_hex(line)
		ptxt, key, score, unprintable = break_single_char_xor(ctxt)
		if score < best_score or (score == best_score and unprintable < best_unprintable):
			best_score = score
			best_unprintable = unprintable
			best_key = key
			best_ptxt = ptxt
			best_idx = idx
	return best_idx, best_ptxt, best_key

if __name__ == '__main__':
	with open('data/4.txt') as f:
		ctxts = f.read().splitlines()
	print(find_ctxt(ctxts))