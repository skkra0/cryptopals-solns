from tools import decode_hex
from three import break_single_char_xor
def find_ctxt(fname):
	best_score = float('inf')
	best_unprintable = float('inf')
	best_mask = None
	best_ptxt = None
	best_idx = -1

	with open(fname, 'r') as f:
		for idx, line in enumerate(f.read().splitlines()):
			ctxt = decode_hex(line)
			ptxt, mask, score, unprintable = break_single_char_xor(ctxt)
			if score < best_score or (score == best_score and unprintable < best_unprintable):
				best_score = score
				best_unprintable = unprintable
				best_mask = mask
				best_ptxt = ptxt
				best_idx = idx
	return best_idx, best_ptxt, best_mask, best_score

if __name__ == '__main__':
	print(find_ctxt('data/4.txt'))