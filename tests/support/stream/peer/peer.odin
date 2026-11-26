package main

import loopback "../../loopback"

import "base:intrinsics"
import "core:c"
import "core:crypto/aead"
import "core:crypto/sha2"
import "core:fmt"
import "core:hash"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sys/posix"
import "core:thread"
import "core:time"

// Go compress/flate level 6 and compress/gzip default writer. The wire bytes
// are the fixture contract, so this is that encoder rather than core:compress.

SCRATCH :: 16 * 1024
MAX_HEADER :: 64 * 1024
MAX_BODY :: 64 * 1024 * 1024
DIR_PERM :: os.Permissions{.Read_User, .Write_User, .Execute_User}
FILE_PERM :: os.Permissions{.Read_User, .Write_User}

MAX_STORE :: 65535
MAX_MATCH_LEN :: 258
MAX_MATCH_OFFSET :: 1 << 15
TABLE_BITS :: 15
TABLE_SIZE :: 1 << TABLE_BITS
ALLOC_HISTORY :: MAX_STORE * 5
BUFFER_RESET :: i32((1 << 31) - ALLOC_HISTORY - MAX_STORE - 1)
BASE_MATCH_OFFSET :: 1
BASE_MATCH_LENGTH :: 3
HASH_LONG :: 7
PRIME4 :: u32(2654435761)
PRIME7 :: u64(58295818150454627)
LITERAL_COUNT :: 286
OFFSET_CODE_COUNT :: 30
END_BLOCK :: 256
LENGTH_CODES_START :: 257
CODEGEN_COUNT :: 19
BAD_CODE :: 255
MAX_PREDEFINED :: 250
BUFFER_FLUSH :: 246
LENGTH_EXTRA_MIN :: 8
OFFSET_EXTRA_MIN :: 4
MATCH_TYPE :: u32(1) << 30
LENGTH_SHIFT :: 22
OFFSET_MASK :: u32(1 << LENGTH_SHIFT) - 1
MATCH_OFFSET_MASK :: u32(0xffff)
LOG_PENALTY :: 7
MAX_INT32 :: i32(2147483647)

LENGTH_EXTRA: [32]u8 = {
	0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
	3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, 0, 0, 0,
}
LENGTH_BASE: [32]u8 = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20,
	24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 255, 0, 0, 0,
}
OFFSET_EXTRA: [32]u8 = {
	0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
	7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14,
}
OFFSET_COMBINED: [32]u32 = {
	0x0, 0x0, 0x0, 0x0, 0x401, 0x601, 0x802, 0xc02,
	0x1003, 0x1803, 0x2004, 0x3004, 0x4005, 0x6005, 0x8006, 0xc006,
	0x10007, 0x18007, 0x20008, 0x30008, 0x40009, 0x60009, 0x8000a, 0xc000a,
	0x10000b, 0x18000b, 0x20000c, 0x30000c, 0x40000d, 0x60000d, 0x0, 0x0,
}
CODEGEN_ORDER: [19]int = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15}


LENGTH_CODES: [256]u8 = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 9, 9, 10, 10, 11, 11,
	12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15,
	16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17,
	18, 18, 18, 18, 18, 18, 18, 18, 19, 19, 19, 19, 19, 19, 19, 19,
	20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
	21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21,
	22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22,
	23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23,
	24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
	24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
	25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
	25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
	26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
	26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
	27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
	27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 28,
}
OFFSET_CODES: [256]u32 = {
	0, 1, 2, 3, 4, 4, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
	8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9,
	10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
	11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
	12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
	12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
	13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
	13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
	15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
	15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
	15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
	15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
}


Literal_Node :: struct {
	literal: u16,
	freq:    u16,
}

Level_Info :: struct {
	level:          i32,
	last_freq:      i32,
	next_char_freq: i32,
	next_pair_freq: i32,
	needed:         i32,
}

Huffman :: struct {
	codes:     []u32,
	bit_count: [17]i32,
	freqcache: [LITERAL_COUNT + 1]Literal_Node,
}

Tokens :: struct {
	extra_hist: [32]u16,
	off_hist:   [32]u16,
	lit_hist:   [256]u16,
	n_filled:   int,
	n:          int,
	tokens:     []u32,
}

Fast :: struct {
	hist:     []u8,
	hist_len: int,
	cur:      i32,
	table:    []i32,
	b_cur:    []i32,
	b_prev:   []i32,
}

Bit_Writer :: struct {
	out:             ^[dynamic]u8,
	bits:            u64,
	nbits:           int,
	nbytes:          int,
	wrote_huffman:   bool,
	literal:         Huffman,
	tmp_lit:         Huffman,
	offset:          Huffman,
	codegen_enc:     Huffman,
	prev_header:     int,
	literal_freq:    [LENGTH_CODES_START + 32]u16,
	offset_freq:     [32]u16,
	codegen_freq:    [CODEGEN_COUNT]u16,
	codegen:         [LITERAL_COUNT + OFFSET_CODE_COUNT + 1]u8,
	bytes:           [256 + 8]u8,
}

Comp :: struct {
	w:          Bit_Writer,
	window:     []u8,
	window_end: i32,
	tokens:     Tokens,
	fast:       Fast,
	sync:       bool,
	out:        [dynamic]u8,
}

fixed_lit: Huffman
fixed_off: Huffman
huff_off: Huffman
tables_ready: bool

fail :: proc(reason: string) {
	fmt.eprintf("stream104 peer: %s\n", reason)
	_ = os.flush(os.stderr)
	loopback.identity_clear()
	os.exit(1)
}

require :: proc(ok: bool, message: string) {
	if !ok {
		fail(message)
	}
}

hcode_new :: proc(code: u16, length: u8) -> u32 {
	return u32(length) | u32(code) << 8
}

hcode_len :: proc(code: u32) -> int {
	return int(u8(code))
}

hcode_bits :: proc(code: u32) -> u64 {
	return u64(code >> 8)
}

reverse_code :: proc(x: u16, b: u8) -> u16 {
	shift := uint((16 - int(b)) & 15)
	return intrinsics.reverse_bits(x << shift)
}

huffman_init :: proc(h: ^Huffman, size: int) {
	h.codes = make([]u32, size)
}

sort_nodes :: proc(list: []Literal_Node, by_freq: bool) {
	for i in 1 ..< len(list) {
		item := list[i]
		j := i
		for j > 0 {
			prev := list[j - 1]
			less := item.literal < prev.literal
			if by_freq {
				less = (int(item.freq) << 10) + int(item.literal) < (int(prev.freq) << 10) + int(prev.literal)
			}
			if !less {
				break
			}
			list[j] = prev
			j -= 1
		}
		list[j] = item
	}
}

bit_counts :: proc(h: ^Huffman, count: int, max_bits: i32) -> []i32 {
	list := h.freqcache[:]
	n := count
	list[n] = Literal_Node{65535, 65535}
	limit := max_bits
	if limit > i32(n) - 1 {
		limit = i32(n) - 1
	}
	levels: [17]Level_Info
	leaf: [16][16]i32
	top := int(limit)
	for level in 1 ..= top {
		levels[level] = Level_Info{
			level = i32(level),
			last_freq = i32(list[1].freq),
			next_char_freq = i32(list[2].freq),
			next_pair_freq = i32(list[0].freq) + i32(list[1].freq),
		}
		leaf[level][level] = 2
		if level == 1 {
			levels[level].next_pair_freq = MAX_INT32
		}
	}
	levels[top].needed = 2 * i32(n) - 4
	level := top
	for level < 16 {
		l := &levels[level]
		if l.next_pair_freq == MAX_INT32 && l.next_char_freq == MAX_INT32 {
			l.needed = 0
			levels[level + 1].next_pair_freq = MAX_INT32
			level += 1
			continue
		}
		prev_freq := l.last_freq
		if l.next_char_freq < l.next_pair_freq {
			nn := leaf[level][level] + 1
			l.last_freq = l.next_char_freq
			leaf[level][level] = nn
			e := list[int(nn)]
			if e.literal < 65535 {
				l.next_char_freq = i32(e.freq)
			} else {
				l.next_char_freq = MAX_INT32
			}
		} else {
			l.last_freq = l.next_pair_freq
			save := leaf[level][level]
			leaf[level] = leaf[level - 1]
			leaf[level][level] = save
			levels[int(l.level) - 1].needed = 2
		}
		l.needed -= 1
		if l.needed == 0 {
			if l.level == limit {
				break
			}
			levels[int(l.level) + 1].next_pair_freq = prev_freq + l.last_freq
			level += 1
		} else {
			for levels[level - 1].needed > 0 {
				level -= 1
			}
		}
	}
	if leaf[top][top] != i32(n) {
		fail("huffman leaf count")
	}
	for i in 0 ..< len(h.bit_count) {
		h.bit_count[i] = 0
	}
	bits := 1
	for lv := top; lv > 0; lv -= 1 {
		h.bit_count[bits] = leaf[top][lv] - leaf[top][lv - 1]
		bits += 1
	}
	return h.bit_count[:top + 1]
}

assign_encoding :: proc(h: ^Huffman, bit_count: []i32, list: []Literal_Node) {
	rest := list
	code := u16(0)
	for n in 0 ..< len(bit_count) {
		code <<= 1
		count := int(bit_count[n])
		if n == 0 || count == 0 {
			continue
		}
		chunk := rest[len(rest) - count:]
		sort_nodes(chunk, false)
		for i in 0 ..< len(chunk) {
			h.codes[chunk[i].literal] = hcode_new(reverse_code(code, u8(n)), u8(n))
			code += 1
		}
		rest = rest[:len(rest) - count]
	}
}

huffman_generate :: proc(h: ^Huffman, freq: []u16, max_bits: i32) {
	count := 0
	for i in 0 ..< len(freq) {
		f := freq[i]
		if f != 0 {
			h.freqcache[count] = Literal_Node{u16(i), f}
			count += 1
		} else if i < len(h.codes) {
			h.codes[i] = 0
		}
	}
	h.freqcache[count] = {}
	if count <= 2 {
		for i in 0 ..< count {
			node := h.freqcache[i]
			h.codes[node.literal] = hcode_new(u16(i), 1)
		}
		return
	}
	sort_nodes(h.freqcache[:count], true)
	counts := bit_counts(h, count, max_bits)
	assign_encoding(h, counts, h.freqcache[:count])
}

bit_length :: proc(codes: []u32, freq: []u16) -> int {
	total := 0
	n := len(freq) if len(freq) < len(codes) else len(codes)
	for i in 0 ..< len(freq) {
		f := freq[i]
		if f == 0 {
			continue
		}
		if i >= n {
			fail("huffman frequency past codes")
		}
		total += int(f) * hcode_len(codes[i])
	}
	return total
}

can_encode_len :: proc(codes: []u32, freq: []u16) -> int {
	total := 0
	for i in 0 ..< len(freq) {
		f := freq[i]
		if f == 0 {
			continue
		}
		code := codes[i]
		if code == 0 {
			return int(MAX_INT32)
		}
		total += int(f) * hcode_len(code)
	}
	return total
}

ensure_tables :: proc() {
	if tables_ready {
		return
	}
	huffman_init(&fixed_lit, LITERAL_COUNT)
	for ch in 0 ..< LITERAL_COUNT {
		bits: u16
		size: u8
		if ch < 144 {
			bits = u16(ch) + 48
			size = 8
		} else if ch < 256 {
			bits = u16(ch) + 400 - 144
			size = 9
		} else if ch < 280 {
			bits = u16(ch) - 256
			size = 7
		} else {
			bits = u16(ch) + 192 - 280
			size = 8
		}
		fixed_lit.codes[ch] = hcode_new(reverse_code(bits, size), size)
	}
	huffman_init(&fixed_off, OFFSET_CODE_COUNT)
	for ch in 0 ..< OFFSET_CODE_COUNT {
		fixed_off.codes[ch] = hcode_new(reverse_code(u16(ch), 5), 5)
	}
	huffman_init(&huff_off, OFFSET_CODE_COUNT)
	freq: [OFFSET_CODE_COUNT]u16
	freq[0] = 1
	huffman_generate(&huff_off, freq[:], 15)
	tables_ready = true
}

m_fast_log2 :: proc(val: f32) -> f32 {
	ux := transmute(i32)(transmute(u32)val)
	log2 := f32(((ux >> 23) & 255) - 128)
	ux &= transmute(i32)u32(0x807fffff)
	ux += 127 << 23
	uval := transmute(f32)u32(ux)
	neg := transmute(f32)u32(0xbeb08ff9)
	pos := transmute(f32)u32(0x40019420)
	bias := transmute(f32)u32(0x3f2cc4c7)
	log2 += ((neg * uval + pos) * uval) - bias
	return log2
}

estimated_bits :: proc(t: ^Tokens) -> int {
	shannon := f32(0)
	bits := 0
	matches := 0
	total := t.n + t.n_filled
	if total > 0 {
		inv := f32(1) / f32(total)
		for i in 0 ..< 256 {
			v := t.lit_hist[i]
			if v > 0 {
				n := f32(v)
				shannon += min(f32(15), max(f32(1), -m_fast_log2(n * inv))) * n
			}
		}
		shannon += 15
		// Go ranges extraHist[1:literalCount-256], so length extra bits are indexed one below the symbol.
		for i in 1 ..< LITERAL_COUNT - 256 {
			v := t.extra_hist[i]
			if v > 0 {
				n := f32(v)
				shannon += min(f32(15), max(f32(1), -m_fast_log2(n * inv))) * n
				bits += int(LENGTH_EXTRA[(i - 1) & 31]) * int(v)
				matches += int(v)
			}
		}
	}
	if matches > 0 {
		inv := f32(1) / f32(matches)
		for i in 0 ..< OFFSET_CODE_COUNT {
			v := t.off_hist[i]
			if v > 0 {
				n := f32(v)
				shannon += min(f32(15), max(f32(1), -m_fast_log2(n * inv))) * n
				bits += int(OFFSET_EXTRA[i & 31]) * int(v)
			}
		}
	}
	return int(shannon) + bits
}

tokens_reset :: proc(t: ^Tokens) {
	if t.n == 0 {
		return
	}
	t.n = 0
	t.n_filled = 0
	for i in 0 ..< 256 {
		t.lit_hist[i] = 0
	}
	for i in 0 ..< 32 {
		t.extra_hist[i] = 0
		t.off_hist[i] = 0
	}
}

offset_code :: proc(off: u32) -> u32 {
	if off < 256 {
		return OFFSET_CODES[off]
	}
	return OFFSET_CODES[u8(off >> 7)] + 14
}

add_match_long :: proc(t: ^Tokens, xlength: i32, xoffset: u32) {
	oc := offset_code(xoffset)
	stored := xoffset | oc << 16
	length := xlength
	for length > 0 {
		xl := length
		if xl > 258 {
			if xl > 258 + BASE_MATCH_LENGTH {
				xl = 258
			} else {
				xl = 258 - BASE_MATCH_LENGTH
			}
		}
		length -= xl
		xl -= BASE_MATCH_LENGTH
		t.extra_hist[LENGTH_CODES[u8(xl)] + 1] += 1
		t.off_hist[oc & 31] += 1
		t.tokens[t.n] = MATCH_TYPE | u32(xl) << LENGTH_SHIFT | stored
		t.n += 1
	}
}

add_eob :: proc(t: ^Tokens) {
	t.tokens[t.n] = END_BLOCK
	t.extra_hist[0] += 1
	t.n += 1
}

emit_literals :: proc(t: ^Tokens, lit: []u8) {
	for i in 0 ..< len(lit) {
		v := lit[i]
		t.tokens[t.n] = u32(v)
		t.lit_hist[v] += 1
		t.n += 1
	}
}


store_le64 :: proc(b: []u8, v: u64) {
	b[0] = u8(v)
	b[1] = u8(v >> 8)
	b[2] = u8(v >> 16)
	b[3] = u8(v >> 24)
	b[4] = u8(v >> 32)
	b[5] = u8(v >> 40)
	b[6] = u8(v >> 48)
	b[7] = u8(v >> 56)
}

load_le32 :: proc(b: []u8, i: int) -> u32 {
	return u32(b[i]) | u32(b[i + 1]) << 8 | u32(b[i + 2]) << 16 | u32(b[i + 3]) << 24
}

load_le64 :: proc(b: []u8, i: int) -> u64 {
	return u64(b[i]) | u64(b[i + 1]) << 8 | u64(b[i + 2]) << 16 | u64(b[i + 3]) << 24 | u64(b[i + 4]) << 32 | u64(b[i + 5]) << 40 | u64(b[i + 6]) << 48 | u64(b[i + 7]) << 56
}

bit_append :: proc(w: ^Bit_Writer, src: []u8) {
	append(w.out, ..src)
}

flush_bits :: proc(w: ^Bit_Writer) {
	bits := w.bits
	w.bits >>= 48
	w.nbits -= 48
	n := w.nbytes
	store_le64(w.bytes[n:], bits)
	n += 6
	if n >= BUFFER_FLUSH {
		bit_append(w, w.bytes[:n])
		n = 0
	}
	w.nbytes = n
}

write_bits :: proc(w: ^Bit_Writer, b: u32, nb: int) {
	w.bits |= u64(b) << uint(w.nbits & 63)
	w.nbits += nb
	if w.nbits >= 48 {
		flush_bits(w)
	}
}

write_code :: proc(w: ^Bit_Writer, code: u32) {
	w.bits |= hcode_bits(code) << uint(w.nbits & 63)
	w.nbits += hcode_len(code)
	if w.nbits >= 48 {
		flush_bits(w)
	}
}

bit_flush :: proc(w: ^Bit_Writer) {
	if w.prev_header > 0 {
		write_code(w, w.literal.codes[END_BLOCK])
		w.prev_header = 0
	}
	n := w.nbytes
	for w.nbits != 0 {
		w.bytes[n] = u8(w.bits)
		w.bits >>= 8
		if w.nbits > 8 {
			w.nbits -= 8
		} else {
			w.nbits = 0
		}
		n += 1
	}
	w.bits = 0
	if n > 0 {
		bit_append(w, w.bytes[:n])
	}
	w.nbytes = 0
}

write_bytes :: proc(w: ^Bit_Writer, data: []u8) {
	if w.nbits & 7 != 0 {
		fail("writeBytes with unfinished bits")
	}
	n := w.nbytes
	for w.nbits != 0 {
		w.bytes[n] = u8(w.bits)
		w.bits >>= 8
		w.nbits -= 8
		n += 1
	}
	if n != 0 {
		bit_append(w, w.bytes[:n])
	}
	w.nbytes = 0
	bit_append(w, data)
}

generate_codegen :: proc(w: ^Bit_Writer, num_literals, num_offsets: int, lit, off: ^Huffman) {
	for i in 0 ..< len(w.codegen_freq) {
		w.codegen_freq[i] = 0
	}
	codegen := w.codegen[:]
	for i in 0 ..< num_literals {
		codegen[i] = u8(hcode_len(lit.codes[i]))
	}
	for i in 0 ..< num_offsets {
		codegen[num_literals + i] = u8(hcode_len(off.codes[i]))
	}
	codegen[num_literals + num_offsets] = BAD_CODE
	size := codegen[0]
	count := 1
	out_index := 0
	for in_index := 1; size != BAD_CODE; in_index += 1 {
		next_size := codegen[in_index]
		if next_size == size {
			count += 1
			continue
		}
		if size != 0 {
			codegen[out_index] = size
			out_index += 1
			w.codegen_freq[size] += 1
			count -= 1
			for count >= 3 {
				n := min(6, count)
				codegen[out_index] = 16
				out_index += 1
				codegen[out_index] = u8(n - 3)
				out_index += 1
				w.codegen_freq[16] += 1
				count -= n
			}
		} else {
			for count >= 11 {
				n := min(138, count)
				codegen[out_index] = 18
				out_index += 1
				codegen[out_index] = u8(n - 11)
				out_index += 1
				w.codegen_freq[18] += 1
				count -= n
			}
			if count >= 3 {
				codegen[out_index] = 17
				out_index += 1
				codegen[out_index] = u8(count - 3)
				out_index += 1
				w.codegen_freq[17] += 1
				count = 0
			}
		}
		count -= 1
		for count >= 0 {
			codegen[out_index] = size
			out_index += 1
			w.codegen_freq[size] += 1
			count -= 1
		}
		size = next_size
		count = 1
	}
	codegen[out_index] = BAD_CODE
}

codegens_count :: proc(w: ^Bit_Writer) -> int {
	num := len(w.codegen_freq)
	for num > 4 && w.codegen_freq[CODEGEN_ORDER[num - 1]] == 0 {
		num -= 1
	}
	return num
}

header_size :: proc(w: ^Bit_Writer) -> (size, num: int) {
	num = codegens_count(w)
	size = 3 + 5 + 5 + 4 + (3 * num) + bit_length(w.codegen_enc.codes[:], w.codegen_freq[:]) + int(w.codegen_freq[16]) * 2 + int(w.codegen_freq[17]) * 3 + int(w.codegen_freq[18]) * 7
	return
}

dynamic_reuse_size :: proc(w: ^Bit_Writer) -> int {
	return bit_length(w.literal.codes[:], w.literal_freq[:]) + bit_length(w.offset.codes[:], w.offset_freq[:])
}

dynamic_size :: proc(w: ^Bit_Writer, extra: int) -> (size, num: int) {
	header, num_codes := header_size(w)
	size = header + bit_length(w.literal.codes[:], w.literal_freq[:]) + bit_length(w.offset.codes[:], w.offset_freq[:]) + extra
	num = num_codes
	return
}

extra_bit_size :: proc(w: ^Bit_Writer) -> int {
	total := 0
	for i in 0 ..< LITERAL_COUNT - 257 {
		n := w.literal_freq[257 + i]
		total += int(n) * int(LENGTH_EXTRA[i & 31])
	}
	for i in 0 ..< OFFSET_CODE_COUNT {
		total += int(w.offset_freq[i]) * int(OFFSET_EXTRA[i & 31])
	}
	return total
}

fixed_size :: proc(w: ^Bit_Writer, extra: int) -> int {
	return 3 + bit_length(fixed_lit.codes[:], w.literal_freq[:]) + bit_length(fixed_off.codes[:], w.offset_freq[:]) + extra
}

stored_size :: proc(n: int) -> (int, bool) {
	if n <= MAX_STORE {
		return (n + 5) * 8, true
	}
	return 0, false
}

write_dynamic_header :: proc(w: ^Bit_Writer, num_literals, num_offsets, num_codegens: int, is_eof: bool) {
	first: u32 = 4
	if is_eof {
		first = 5
	}
	write_bits(w, first, 3)
	write_bits(w, u32(num_literals - 257), 5)
	write_bits(w, u32(num_offsets - 1), 5)
	write_bits(w, u32(num_codegens - 4), 4)
	for i in 0 ..< num_codegens {
		value := hcode_len(w.codegen_enc.codes[CODEGEN_ORDER[i]])
		write_bits(w, u32(value), 3)
	}
	i := 0
	for {
		code_word := u32(w.codegen[i])
		i += 1
		if code_word == BAD_CODE {
			break
		}
		write_code(w, w.codegen_enc.codes[code_word])
		if code_word == 16 {
			write_bits(w, u32(w.codegen[i]), 2)
			i += 1
		} else if code_word == 17 {
			write_bits(w, u32(w.codegen[i]), 3)
			i += 1
		} else if code_word == 18 {
			write_bits(w, u32(w.codegen[i]), 7)
			i += 1
		}
	}
}

write_fixed_header :: proc(w: ^Bit_Writer, is_eof: bool) {
	if w.prev_header > 0 {
		write_code(w, w.literal.codes[END_BLOCK])
		w.prev_header = 0
	}
	value: u32 = 2
	if is_eof {
		value = 3
	}
	write_bits(w, value, 3)
}

write_stored_header :: proc(w: ^Bit_Writer, length: int, is_eof: bool) {
	if w.prev_header > 0 {
		write_code(w, w.literal.codes[END_BLOCK])
		w.prev_header = 0
	}
	if length == 0 && is_eof {
		write_fixed_header(w, true)
		write_bits(w, 0, 7)
		// bit_flush would write another owed EOB. The header path already cleared it.
		n := w.nbytes
		for w.nbits != 0 {
			w.bytes[n] = u8(w.bits)
			w.bits >>= 8
			if w.nbits > 8 {
				w.nbits -= 8
			} else {
				w.nbits = 0
			}
			n += 1
		}
		w.bits = 0
		if n > 0 {
			bit_append(w, w.bytes[:n])
		}
		w.nbytes = 0
		return
	}
	flag: u32 = 0
	if is_eof {
		flag = 1
	}
	write_bits(w, flag, 3)
	n := w.nbytes
	for w.nbits != 0 {
		w.bytes[n] = u8(w.bits)
		w.bits >>= 8
		if w.nbits > 8 {
			w.nbits -= 8
		} else {
			w.nbits = 0
		}
		n += 1
	}
	w.bits = 0
	if n > 0 {
		bit_append(w, w.bytes[:n])
	}
	w.nbytes = 0
	write_bits(w, u32(length), 16)
	write_bits(w, u32(~(u16(length))), 16)
}

index_tokens :: proc(w: ^Bit_Writer, t: ^Tokens) -> (num_literals, num_offsets: int) {
	for i in 0 ..< 256 {
		w.literal_freq[i] = t.lit_hist[i]
	}
	for i in 0 ..< 32 {
		w.literal_freq[256 + i] = t.extra_hist[i]
	}
	w.literal_freq[288] = 0
	w.offset_freq = t.off_hist
	if t.n == 0 {
		return
	}
	num_literals = len(w.literal_freq)
	for w.literal_freq[num_literals - 1] == 0 {
		num_literals -= 1
	}
	num_offsets = len(w.offset_freq)
	for num_offsets > 0 && w.offset_freq[num_offsets - 1] == 0 {
		num_offsets -= 1
	}
	if num_offsets == 0 {
		w.offset_freq[0] = 1
		num_offsets = 1
	}
	return
}

can_reuse :: proc(w: ^Bit_Writer, t: ^Tokens) -> bool {
	for i in 0 ..< OFFSET_CODE_COUNT {
		if t.off_hist[i] != 0 && w.offset.codes[i] == 0 {
			return false
		}
	}
	for i in 0 ..< LITERAL_COUNT - 256 {
		if t.extra_hist[i] != 0 && w.literal.codes[256 + i] == 0 {
			return false
		}
	}
	for i in 0 ..< 256 {
		if t.lit_hist[i] != 0 && w.literal.codes[i] == 0 {
			return false
		}
	}
	return true
}

generate_encodings :: proc(w: ^Bit_Writer) {
	huffman_generate(&w.literal, w.literal_freq[:LITERAL_COUNT], 15)
	huffman_generate(&w.offset, w.offset_freq[:OFFSET_CODE_COUNT], 15)
}

write_tokens :: proc(w: ^Bit_Writer, tokens: []u32, len_codes, off_codes: []u32) {
	if len(tokens) == 0 {
		return
	}
	view := tokens
	defer_eob := false
	if view[len(view) - 1] == END_BLOCK {
		view = view[:len(view) - 1]
		defer_eob = true
	}
	lits := len_codes[:256]
	bits := w.bits
	nbits := w.nbits
	nbytes := w.nbytes
	for i in 0 ..< len(view) {
		t := view[i]
		if t < 256 {
			c := lits[t]
			bits |= hcode_bits(c) << uint(nbits & 63)
			nbits += hcode_len(c)
			if nbits >= 48 {
				store_le64(w.bytes[nbytes:], bits)
				bits >>= 48
				nbits -= 48
				nbytes += 6
				if nbytes >= BUFFER_FLUSH {
					bit_append(w, w.bytes[:nbytes])
					nbytes = 0
				}
			}
			continue
		}
		length := u8(t >> LENGTH_SHIFT)
		len_code := int(LENGTH_CODES[length] & 31)
		c := len_codes[LENGTH_CODES_START + len_code]
		bits |= hcode_bits(c) << uint(nbits & 63)
		nbits += hcode_len(c)
		if nbits >= 48 {
			store_le64(w.bytes[nbytes:], bits)
			bits >>= 48
			nbits -= 48
			nbytes += 6
			if nbytes >= BUFFER_FLUSH {
				bit_append(w, w.bytes[:nbytes])
				nbytes = 0
			}
		}
		if len_code >= LENGTH_EXTRA_MIN {
			extra := u32(length - LENGTH_BASE[len_code])
			bits |= u64(extra) << uint(nbits & 63)
			nbits += int(LENGTH_EXTRA[len_code])
			if nbits >= 48 {
				store_le64(w.bytes[nbytes:], bits)
				bits >>= 48
				nbits -= 48
				nbytes += 6
				if nbytes >= BUFFER_FLUSH {
					bit_append(w, w.bytes[:nbytes])
					nbytes = 0
				}
			}
		}
		offset := t & OFFSET_MASK
		off_code := int((offset >> 16) & 31)
		c = off_codes[off_code]
		bits |= hcode_bits(c) << uint(nbits & 63)
		nbits += hcode_len(c)
		if nbits >= 48 {
			store_le64(w.bytes[nbytes:], bits)
			bits >>= 48
			nbits -= 48
			nbytes += 6
			if nbytes >= BUFFER_FLUSH {
				bit_append(w, w.bytes[:nbytes])
				nbytes = 0
			}
		}
		if off_code >= OFFSET_EXTRA_MIN {
			comb := OFFSET_COMBINED[off_code]
			extra := (offset - (comb >> 8)) & MATCH_OFFSET_MASK
			bits |= u64(extra) << uint(nbits & 63)
			nbits += int(u8(comb))
			if nbits >= 48 {
				store_le64(w.bytes[nbytes:], bits)
				bits >>= 48
				nbits -= 48
				nbytes += 6
				if nbytes >= BUFFER_FLUSH {
					bit_append(w, w.bytes[:nbytes])
					nbytes = 0
				}
			}
		}
	}
	w.bits = bits
	w.nbits = nbits
	w.nbytes = nbytes
	if defer_eob {
		write_code(w, len_codes[END_BLOCK])
	}
}

write_block_dynamic :: proc(w: ^Bit_Writer, t: ^Tokens, eof: bool, input: []u8, sync: bool) {
	syncing := sync || eof
	if syncing {
		add_eob(t)
	} else {
		t.extra_hist[0] = 1
	}
	if (w.wrote_huffman || eof) && w.prev_header > 0 {
		write_code(w, w.literal.codes[END_BLOCK])
		w.prev_header = 0
		w.wrote_huffman = false
	}
	if w.prev_header > 0 && !can_reuse(w, t) {
		write_code(w, w.literal.codes[END_BLOCK])
		w.prev_header = 0
	}
	num_literals, num_offsets := index_tokens(w, t)
	extra := 0
	ssize, storable := stored_size(len(input))
	if storable || w.prev_header > 0 {
		extra = extra_bit_size(w)
	}
	size := 0
	if w.prev_header > 0 {
		new_size := w.prev_header + estimated_bits(t)
		new_size += hcode_len(w.literal.codes[END_BLOCK]) + (new_size >> LOG_PENALTY)
		reuse_size := dynamic_reuse_size(w) + extra
		if new_size < reuse_size {
			write_code(w, w.literal.codes[END_BLOCK])
			size = new_size
			w.prev_header = 0
		} else {
			size = reuse_size
		}
		if t.n < MAX_PREDEFINED {
			pre := fixed_size(w, extra) + 7
			if pre < size {
				if storable && ssize <= size {
					write_stored_header(w, len(input), eof)
					write_bytes(w, input)
					return
				}
				write_fixed_header(w, eof)
				if !syncing {
					add_eob(t)
				}
				write_tokens(w, t.tokens[:t.n], fixed_lit.codes[:], fixed_off.codes[:])
				return
			}
		}
		if storable && ssize <= size {
			write_stored_header(w, len(input), eof)
			write_bytes(w, input)
			return
		}
	}
	if w.prev_header == 0 {
		w.literal_freq[END_BLOCK] = 1
		generate_encodings(w)
		generate_codegen(w, num_literals, num_offsets, &w.literal, &w.offset)
		huffman_generate(&w.codegen_enc, w.codegen_freq[:], 7)
		num_codegens: int
		size, num_codegens = dynamic_size(w, extra)
		if t.n < MAX_PREDEFINED {
			pre := fixed_size(w, extra)
			if pre <= size {
				if storable && ssize <= pre {
					write_stored_header(w, len(input), eof)
					write_bytes(w, input)
					return
				}
				write_fixed_header(w, eof)
				if !syncing {
					add_eob(t)
				}
				write_tokens(w, t.tokens[:t.n], fixed_lit.codes[:], fixed_off.codes[:])
				return
			}
		}
		if storable && ssize <= size {
			write_stored_header(w, len(input), eof)
			write_bytes(w, input)
			return
		}
		write_dynamic_header(w, num_literals, num_offsets, num_codegens, eof)
		if !syncing {
			w.prev_header, _ = header_size(w)
		}
		w.wrote_huffman = false
	}
	if syncing {
		w.prev_header = 0
	}
	write_tokens(w, t.tokens[:t.n], w.literal.codes[:], w.offset.codes[:])
}

write_block_huff :: proc(w: ^Bit_Writer, eof: bool, input: []u8, sync: bool) {
	for i in 0 ..< len(w.literal_freq) {
		w.literal_freq[i] = 0
	}
	if !w.wrote_huffman {
		for i in 0 ..< len(w.offset_freq) {
			w.offset_freq[i] = 0
		}
	}
	num_literals :: END_BLOCK + 1
	num_offsets :: 1
	for i in 0 ..< len(input) {
		w.literal_freq[input[i]] += 1
	}
	ssize, storable := stored_size(len(input))
	if storable && len(input) > 1024 {
		abs := f64(0)
		avg := f64(len(input)) / 256
		limit := f64(len(input) * 2)
		for i in 0 ..< 256 {
			diff := f64(w.literal_freq[i]) - avg
			abs += diff * diff
			if abs >= limit {
				break
			}
		}
		if abs < limit {
			write_stored_header(w, len(input), eof)
			write_bytes(w, input)
			return
		}
	}
	w.literal_freq[END_BLOCK] = 1
	huffman_generate(&w.tmp_lit, w.literal_freq[:num_literals], 15)
	est := can_encode_len(w.tmp_lit.codes[:], w.literal_freq[:num_literals])
	if est < int(MAX_INT32) {
		est += w.prev_header
		if w.prev_header == 0 {
			est += 70 * 8
		}
		est += est >> LOG_PENALTY
	}
	if storable && ssize <= est {
		write_stored_header(w, len(input), eof)
		write_bytes(w, input)
		return
	}
	if w.prev_header > 0 {
		reuse := can_encode_len(w.literal.codes[:], w.literal_freq[:256])
		if est < reuse {
			write_code(w, w.literal.codes[END_BLOCK])
			w.prev_header = 0
		}
	}
	if w.prev_header == 0 {
		tmp := w.literal
		w.literal = w.tmp_lit
		w.tmp_lit = tmp
		generate_codegen(w, num_literals, num_offsets, &w.literal, &huff_off)
		huffman_generate(&w.codegen_enc, w.codegen_freq[:], 7)
		num_codegens := codegens_count(w)
		write_dynamic_header(w, num_literals, num_offsets, num_codegens, eof)
		w.wrote_huffman = true
		w.prev_header, _ = header_size(w)
	}
	encoding := w.literal.codes[:256]
	bits := w.bits
	nbits := w.nbits
	nbytes := w.nbytes
	src := input
	for len(src) > 3 {
		if nbits >= 8 {
			n := nbits >> 3
			store_le64(w.bytes[nbytes:], bits)
			bits >>= uint((n * 8) & 63)
			nbits -= n * 8
			nbytes += n
		}
		if nbytes >= BUFFER_FLUSH {
			bit_append(w, w.bytes[:nbytes])
			nbytes = 0
		}
		a, b := encoding[src[0]], encoding[src[1]]
		bits |= hcode_bits(a) << uint(nbits & 63)
		bits |= hcode_bits(b) << uint((nbits + hcode_len(a)) & 63)
		c := encoding[src[2]]
		nbits += hcode_len(b) + hcode_len(a)
		bits |= hcode_bits(c) << uint(nbits & 63)
		nbits += hcode_len(c)
		src = src[3:]
	}
	for i in 0 ..< len(src) {
		if nbits >= 48 {
			store_le64(w.bytes[nbytes:], bits)
			bits >>= 48
			nbits -= 48
			nbytes += 6
			if nbytes >= BUFFER_FLUSH {
				bit_append(w, w.bytes[:nbytes])
				nbytes = 0
			}
		}
		c := encoding[src[i]]
		bits |= hcode_bits(c) << uint(nbits & 63)
		nbits += hcode_len(c)
	}
	w.bits = bits
	w.nbits = nbits
	w.nbytes = nbytes
	if w.nbits >= 48 {
		flush_bits(w)
	}
	if eof || sync {
		write_code(w, w.literal.codes[END_BLOCK])
		w.prev_header = 0
		w.wrote_huffman = false
	}
}


hash_len :: proc(u: u64, b, n: int) -> u32 {
	if n == 7 {
		return u32(((u << 8) * PRIME7) >> uint(64 - b))
	}
	return (u32(u) * PRIME4) >> uint(32 - b)
}

match_len :: proc(a, b: []u8) -> int {
	n := 0
	left := len(a)
	for left >= 8 {
		diff := load_le64(a, n) ~ load_le64(b, n)
		if diff != 0 {
			return n + int(intrinsics.count_trailing_zeros(diff) >> 3)
		}
		n += 8
		left -= 8
	}
	aa := a[n:]
	bb := b[n:][:len(aa)]
	for i in 0 ..< len(aa) {
		if aa[i] != bb[i] {
			break
		}
		n += 1
	}
	return n
}

match_len_limited :: proc(s, t: int, src: []u8) -> i32 {
	end := s + MAX_MATCH_LEN - 4
	if end > len(src) {
		end = len(src)
	}
	return i32(match_len(src[s:end], src[t:]))
}

match_len_long :: proc(s, t: int, src: []u8) -> i32 {
	return i32(match_len(src[s:], src[t:]))
}

push_entry :: proc(cur, prev: ^i32, entry: i32) {
	old := cur^
	cur^ = entry
	prev^ = old
}

add_block :: proc(e: ^Fast, src: []u8) -> i32 {
	if e.hist == nil {
		e.hist = make([]u8, ALLOC_HISTORY)
		e.hist_len = 0
	}
	if e.hist_len + len(src) > len(e.hist) {
		offset := e.hist_len - MAX_MATCH_OFFSET
		copy(e.hist[:MAX_MATCH_OFFSET], e.hist[offset:][:MAX_MATCH_OFFSET])
		e.cur += i32(offset)
		e.hist_len = MAX_MATCH_OFFSET
	}
	s := i32(e.hist_len)
	copy(e.hist[e.hist_len:], src)
	e.hist_len += len(src)
	return s
}

fast_reset :: proc(e: ^Fast) {
	if e.hist == nil || len(e.hist) < ALLOC_HISTORY {
		e.hist = make([]u8, ALLOC_HISTORY)
	}
	if e.cur <= BUFFER_RESET {
		e.cur += MAX_MATCH_OFFSET + i32(e.hist_len)
	}
	e.hist_len = 0
}

fast_encode :: proc(e: ^Fast, dst: ^Tokens, src_in: []u8) {
	input_margin :: 12 - 1
	min_block :: 1 + 1 + input_margin
	if e.cur >= BUFFER_RESET {
		if e.hist_len == 0 {
			for i in 0 ..< TABLE_SIZE {
				e.table[i] = 0
				e.b_cur[i] = 0
				e.b_prev[i] = 0
			}
			e.cur = MAX_MATCH_OFFSET
		} else {
			min_off := e.cur + i32(e.hist_len) - MAX_MATCH_OFFSET
			for i in 0 ..< TABLE_SIZE {
				v := e.table[i]
				if v <= min_off {
					v = 0
				} else {
					v = v - e.cur + MAX_MATCH_OFFSET
				}
				e.table[i] = v
				cur := e.b_cur[i]
				prev := e.b_prev[i]
				if cur <= min_off {
					cur = 0
					prev = 0
				} else {
					cur = cur - e.cur + MAX_MATCH_OFFSET
					if prev <= min_off {
						prev = 0
					} else {
						prev = prev - e.cur + MAX_MATCH_OFFSET
					}
				}
				e.b_cur[i] = cur
				e.b_prev[i] = prev
			}
			e.cur = MAX_MATCH_OFFSET
		}
	}
	s := add_block(e, src_in)
	if len(src_in) < min_block {
		dst.n = len(src_in)
		return
	}
	src := e.hist[:e.hist_len]
	next_emit := s
	s_limit := i32(len(src) - input_margin)
	cv := load_le64(src, int(s))
	repeat := i32(1)
	search: for {
		next_s := s
		l := i32(0)
		t := i32(0)
		for {
			next_hash_s := hash_len(cv, TABLE_BITS, 4)
			next_hash_l := hash_len(cv, TABLE_BITS, HASH_LONG)
			s = next_s
			next_s = s + 1 + (s - next_emit) >> 7
			if next_s > s_limit {
				break search
			}
			s_candidate := e.table[next_hash_s]
			l_cur := e.b_cur[next_hash_l]
			l_prev := e.b_prev[next_hash_l]
			next := load_le64(src, int(next_s))
			entry := s + e.cur
			e.table[next_hash_s] = entry
			push_entry(&e.b_cur[next_hash_l], &e.b_prev[next_hash_l], entry)
			next_hash_s = hash_len(next, TABLE_BITS, 4)
			next_hash_l = hash_len(next, TABLE_BITS, HASH_LONG)
			t = l_cur - e.cur
			if s - t < MAX_MATCH_OFFSET {
				if u32(cv) == load_le32(src, int(t)) {
					e.table[next_hash_s] = next_s + e.cur
					push_entry(&e.b_cur[next_hash_l], &e.b_prev[next_hash_l], next_s + e.cur)
					t2 := l_prev - e.cur
					if s - t2 < MAX_MATCH_OFFSET && u32(cv) == load_le32(src, int(t2)) {
						l = match_len_limited(int(s + 4), int(t + 4), src) + 4
						ml1 := match_len_limited(int(s + 4), int(t2 + 4), src) + 4
						if ml1 > l {
							t = t2
							l = ml1
							break
						}
					}
					break
				}
				t = l_prev - e.cur
				if s - t < MAX_MATCH_OFFSET && u32(cv) == load_le32(src, int(t)) {
					e.table[next_hash_s] = next_s + e.cur
					push_entry(&e.b_cur[next_hash_l], &e.b_prev[next_hash_l], next_s + e.cur)
					break
				}
			}
			t = s_candidate - e.cur
			if s - t < MAX_MATCH_OFFSET && u32(cv) == load_le32(src, int(t)) {
				l = match_len_limited(int(s + 4), int(t + 4), src) + 4
				l_cur = e.b_cur[next_hash_l]
				l_prev = e.b_prev[next_hash_l]
				e.table[next_hash_s] = next_s + e.cur
				push_entry(&e.b_cur[next_hash_l], &e.b_prev[next_hash_l], next_s + e.cur)
				t2 := s - repeat + 1
				if load_le32(src, int(t2)) == u32(cv >> 8) {
					ml := match_len_limited(int(s + 4 + 1), int(t2 + 4), src) + 4
					if ml > l {
						t = t2
						l = ml
						s += 1
						break
					}
				}
				t2 = l_cur - e.cur
				if next_s - t2 < MAX_MATCH_OFFSET {
					if load_le32(src, int(t2)) == u32(next) {
						ml := match_len_limited(int(next_s + 4), int(t2 + 4), src) + 4
						if ml > l {
							t = t2
							s = next_s
							l = ml
						}
					}
					t2 = l_prev - e.cur
					if next_s - t2 < MAX_MATCH_OFFSET && load_le32(src, int(t2)) == u32(next) {
						ml := match_len_limited(int(next_s + 4), int(t2 + 4), src) + 4
						if ml > l {
							t = t2
							s = next_s
							l = ml
							break
						}
					}
				}
				break
			}
			cv = next
		}
		if l == 0 {
			l = match_len_long(int(s + 4), int(t + 4), src) + 4
		} else if l == MAX_MATCH_LEN {
			l += match_len_long(int(s + l), int(t + l), src)
		}
		s_at := s + l
		if s_at < s_limit {
			skip := i32(2)
			idx := hash_len(load_le64(src, int(s_at)), TABLE_BITS, HASH_LONG)
			t2 := e.b_cur[idx] - e.cur - l + skip
			s2 := s + skip
			off := s2 - t2
			if off < MAX_MATCH_OFFSET {
				if off > 0 && t2 >= 0 {
					l2 := match_len_long(int(s2), int(t2), src)
					if l2 > l {
						t = t2
						l = l2
						s = s2
					}
				}
				t2 = e.b_prev[idx] - e.cur - l + skip
				off = s2 - t2
				if off > 0 && off < MAX_MATCH_OFFSET && t2 >= 0 {
					l2 := match_len_long(int(s2), int(t2), src)
					if l2 > l {
						t = t2
						l = l2
						s = s2
					}
				}
			}
		}
		for t > 0 && s > next_emit && src[t - 1] == src[s - 1] {
			s -= 1
			t -= 1
			l += 1
		}
		if next_emit < s {
			emit_literals(dst, src[int(next_emit):int(s)])
		}
		add_match_long(dst, l, u32(s - t - BASE_MATCH_OFFSET))
		repeat = s - t
		s += l
		next_emit = s
		if next_s >= s {
			s = next_s + 1
		}
		if s >= s_limit {
			for i := next_s + 1; i < i32(len(src) - 8); i += 2 {
				hv := load_le64(src, int(i))
				e.table[hash_len(hv, TABLE_BITS, 4)] = i + e.cur
				push_entry(&e.b_cur[hash_len(hv, TABLE_BITS, HASH_LONG)], &e.b_prev[hash_len(hv, TABLE_BITS, HASH_LONG)], i + e.cur)
			}
			break search
		}
		for i := next_s + 1; i < s - 1; i += 2 {
			hv := load_le64(src, int(i))
			cur_off := i + e.cur
			e.table[hash_len(hv, TABLE_BITS, 4)] = cur_off
			push_entry(&e.b_cur[hash_len(hv, TABLE_BITS, HASH_LONG)], &e.b_prev[hash_len(hv, TABLE_BITS, HASH_LONG)], cur_off)
			push_entry(&e.b_cur[hash_len(hv >> 8, TABLE_BITS, HASH_LONG)], &e.b_prev[hash_len(hv >> 8, TABLE_BITS, HASH_LONG)], cur_off + 1)
		}
		cv = load_le64(src, int(s))
	}
	if int(next_emit) < len(src) && dst.n != 0 {
		emit_literals(dst, src[int(next_emit):])
	}
}

write_stored_block :: proc(d: ^Comp, buf: []u8) {
	write_stored_header(&d.w, len(buf), false)
	write_bytes(&d.w, buf)
}

deflate_fast :: proc(d: ^Comp) {
	if int(d.window_end) < len(d.window) {
		if !d.sync {
			return
		}
		if d.window_end < 128 {
			if d.window_end == 0 {
				return
			}
			if d.window_end <= 32 {
				write_stored_block(d, d.window[:d.window_end])
			} else {
				write_block_huff(&d.w, false, d.window[:d.window_end], true)
			}
			tokens_reset(&d.tokens)
			d.window_end = 0
			fast_reset(&d.fast)
			return
		}
	}
	fast_encode(&d.fast, &d.tokens, d.window[:d.window_end])
	if d.tokens.n == 0 {
		write_stored_block(d, d.window[:d.window_end])
	} else if d.tokens.n > int(d.window_end - (d.window_end >> 4)) {
		write_block_huff(&d.w, false, d.window[:d.window_end], d.sync)
	} else {
		write_block_dynamic(&d.w, &d.tokens, false, d.window[:d.window_end], d.sync)
	}
	tokens_reset(&d.tokens)
	d.window_end = 0
}

fill_block :: proc(d: ^Comp, b: []u8) -> int {
	n := copy(d.window[d.window_end:], b)
	d.window_end += i32(n)
	return n
}

comp_write :: proc(d: ^Comp, b: []u8) {
	rest := b
	for len(rest) > 0 {
		if int(d.window_end) == len(d.window) {
			deflate_fast(d)
		}
		n := fill_block(d, rest)
		rest = rest[n:]
	}
}

comp_close :: proc(d: ^Comp) {
	d.sync = true
	deflate_fast(d)
	write_stored_header(&d.w, 0, true)
	n := d.w.nbytes
	for d.w.nbits != 0 {
		d.w.bytes[n] = u8(d.w.bits)
		d.w.bits >>= 8
		if d.w.nbits > 8 {
			d.w.nbits -= 8
		} else {
			d.w.nbits = 0
		}
		n += 1
	}
	d.w.bits = 0
	if n > 0 {
		bit_append(&d.w, d.w.bytes[:n])
	}
	d.w.nbytes = 0
}

new_comp :: proc() -> ^Comp {
	ensure_tables()
	d := new(Comp)
	d.window = make([]u8, MAX_STORE)
	d.fast.table = make([]i32, TABLE_SIZE)
	d.fast.b_cur = make([]i32, TABLE_SIZE)
	d.fast.b_prev = make([]i32, TABLE_SIZE)
	d.fast.cur = MAX_STORE
	d.tokens.tokens = make([]u32, 65536)
	huffman_init(&d.w.literal, LITERAL_COUNT)
	huffman_init(&d.w.tmp_lit, LITERAL_COUNT)
	huffman_init(&d.w.offset, OFFSET_CODE_COUNT)
	huffman_init(&d.w.codegen_enc, CODEGEN_COUNT)
	d.w.out = &d.out
	return d
}

free_comp :: proc(d: ^Comp) {
	delete(d.window)
	delete(d.fast.hist)
	delete(d.fast.table)
	delete(d.fast.b_cur)
	delete(d.fast.b_prev)
	delete(d.tokens.tokens)
	delete(d.w.literal.codes)
	delete(d.w.tmp_lit.codes)
	delete(d.w.offset.codes)
	delete(d.w.codegen_enc.codes)
	free(d)
}

gzip_payload :: proc(size: int, repeated, metadata: bool) -> [dynamic]u8 {
	d := new_comp()
	header := [10]u8{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255}
	if metadata {
		header[3] = 0x1c
	}
	append(&d.out, ..header[:])
	if metadata {
		extra := [37]u8{}
		for i in 0 ..< 37 {
			extra[i] = 0x19
		}
		append(&d.out, u8(37), u8(0))
		append(&d.out, ..extra[:])
		name := "fixture.bin"
		append(&d.out, ..transmute([]u8)name)
		append(&d.out, 0)
		comment := "owned independent metadata"
		append(&d.out, ..transmute([]u8)comment)
		append(&d.out, 0)
	}
	crc: u32
	block: [SCRATCH]u8
	for at := 0; at < size; {
		n := min(SCRATCH, size - at)
		if repeated {
			for i in 0 ..< n {
				block[i] = 'A'
			}
		} else {
			pattern_at(block[:n], at)
		}
		crc = hash.crc32(block[:n], crc)
		comp_write(d, block[:n])
		at += n
	}
	comp_close(d)
	append(&d.out, u8(crc), u8(crc >> 8), u8(crc >> 16), u8(crc >> 24))
	sz := u32(size)
	append(&d.out, u8(sz), u8(sz >> 8), u8(sz >> 16), u8(sz >> 24))
	out := d.out
	free_comp(d)
	require(len(out) <= MAX_BODY, "compressed fixture bound")
	return out
}

pattern_at :: proc(dst: []u8, offset: int) {
	for i in 0 ..< len(dst) {
		at := offset + i
		dst[i] = u8((at * 31 + at / 251 + 17) % 256)
	}
}

hex_digits: string = "0123456789abcdef"

Link :: struct {
	fd:          net.TCP_Socket,
	conn:        loopback.Conn,
	encrypted:   bool,
	established: bool,
	closed:      bool,
}

Reader :: struct {
	link: ^Link,
	buf:  [SCRATCH]u8,
	r:    int,
	w:    int,
	err:  bool,
}

Field :: struct {
	name:  string,
	value: string,
}

// Strings alias the header storage passed to read_head.
Request :: struct {
	method:        string,
	target:        string,
	length:        int,
	accept:        string,
	authorization: string,
}

Fixture :: struct {
	mode:                     string,
	directory:                string,
	size:                     int,
	encrypted:                bool,
	barrier:                  bool,
	listener:                 net.TCP_Socket,
	encoded:                  [dynamic]u8,
	body_sha:                 [64]u8,
	body_sha_n:               int,
	upload_sha:               [64]u8,
	upload_sha_n:             int,
	alpn:                     [40]u8,
	alpn_n:                   int,
	accept_buf:               [1024]u8,
	accept_n:                 int,
	requests:                 int,
	wire:                     int,
	decoded:                  int,
	upload_bytes:             int,
	upload_complete:          bool,
	first_chunk_barrier:      bool,
	early_final:              bool,
	authorization_gone:       bool,
	intermediate_sent:        bool,
	cheap_before_release:     bool,
	deadline_handshake_abort: bool,
}

Cheap_Job :: struct {
	listener:  net.TCP_Socket,
	directory: string,
	ok:        bool,
}

Closer :: struct {
	fd:   net.TCP_Socket,
	open: bool,
}

Read_Kind :: enum {
	Line,
	Full,
	Error,
}

free_tables :: proc() {
	if !tables_ready {
		return
	}
	delete(fixed_lit.codes)
	delete(fixed_off.codes)
	delete(huff_off.codes)
	fixed_lit.codes = nil
	fixed_off.codes = nil
	huff_off.codes = nil
	tables_ready = false
}

delete_encoded :: proc(f: ^Fixture) {
	delete(f.encoded)
	f.encoded = nil
}

close_closer :: proc(c: ^Closer) {
	if c.open {
		net.close(c.fd)
		c.open = false
	}
}

bytes_of :: proc(s: string) -> []u8 {
	if len(s) == 0 {
		return nil
	}
	return ([^]u8)(raw_data(s))[:len(s)]
}

hex_encode :: proc(dst, raw: []u8) -> int {
	for i in 0 ..< len(raw) {
		dst[i * 2] = hex_digits[int(raw[i] >> 4)]
		dst[i * 2 + 1] = hex_digits[int(raw[i] & 15)]
	}
	return len(raw) * 2
}

finish_sha :: proc(ctx: ^sha2.Context_256, dst: []u8) -> int {
	raw: [32]u8
	sha2.final(ctx, raw[:])
	return hex_encode(dst, raw[:])
}

digest_pattern :: proc(size: int, dst: []u8) -> int {
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	block: [SCRATCH]u8
	for at := 0; at < size; {
		n := min(SCRATCH, size - at)
		pattern_at(block[:n], at)
		sha2.update(&ctx, block[:n])
		at += n
	}
	return finish_sha(&ctx, dst)
}

digest_repeat :: proc(size: int, dst: []u8) -> int {
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	block: [SCRATCH]u8
	for i in 0 ..< SCRATCH {
		block[i] = 'A'
	}
	for at := 0; at < size; {
		n := min(SCRATCH, size - at)
		sha2.update(&ctx, block[:n])
		at += n
	}
	return finish_sha(&ctx, dst)
}

digest_bytes :: proc(payload, dst: []u8) -> int {
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	if len(payload) > 0 {
		sha2.update(&ctx, payload)
	}
	return finish_sha(&ctx, dst)
}

join_path :: proc(buf: []u8, dir, name: string) -> string {
	extra := 1
	if len(dir) > 0 && dir[len(dir) - 1] == '/' {
		extra = 0
	}
	if len(dir) + extra + len(name) > len(buf) {
		fail("path")
	}
	n := copy(buf, dir)
	if n == 0 || buf[n - 1] != '/' {
		buf[n] = '/'
		n += 1
	}
	n += copy(buf[n:], name)
	return string(buf[:n])
}

marker :: proc(f: ^Fixture, name: string) {
	path: [4096]u8
	p := join_path(path[:], f.directory, name)
	if os.write_entire_file(p, name, FILE_PERM) != nil {
		fail("marker")
	}
}

wait_file :: proc(f: ^Fixture, name: string) {
	path: [4096]u8
	p := join_path(path[:], f.directory, name)
	deadline := time.time_add(time.now(), 12 * time.Second)
	for time.diff(deadline, time.now()) <= 0 {
		if os.exists(p) {
			return
		}
		time.sleep(time.Millisecond)
	}
	msg: [192]u8
	fail(fmt.bprintf(msg[:], "coordination timeout: %s", name))
}

nonce_of :: proc(iv: [12]u8, seq: u64) -> [12]u8 {
	nonce := iv
	rest := seq
	for i in 0 ..< 8 {
		nonce[11 - i] ~= u8(rest)
		rest >>= 8
	}
	return nonce
}

// TLS 1.3 close_notify. loopback has no export for the alert record, so the
// peer seals it with the application write key before the TCP close.
close_notify :: proc(link: ^Link) {
	inner := [3]u8{1, 0, 21}
	cipher: [3]u8
	tag: [16]u8
	header := [5]u8{23, 3, 3, 0, 19}
	nonce := nonce_of(link.conn.out_iv, link.conn.out_seq)
	aead.seal_oneshot(.AES_GCM_128, cipher[:], tag[:], link.conn.out_key[:], nonce[:], header[:], inner[:])
	link.conn.out_seq += 1
	packet: [24]u8
	copy(packet[:5], header[:])
	copy(packet[5:8], cipher[:])
	copy(packet[8:], tag[:])
	rest := packet[:]
	for len(rest) > 0 {
		n, err := net.send_tcp(link.fd, rest)
		if n > 0 {
			rest = rest[n:]
			continue
		}
		if err == .Interrupted {
			continue
		}
		return
	}
}

close_link :: proc(link: ^Link) {
	if link.closed || i64(link.fd) == 0 {
		return
	}
	link.closed = true
	if link.established {
		close_notify(link)
	}
	net.close(link.fd)
	if link.encrypted {
		loopback.conn_wipe(&link.conn)
	}
}

link_read :: proc(link: ^Link, dst: []u8) -> (n: int, bad: bool) {
	if len(dst) == 0 {
		return 0, false
	}
	for {
		if link.encrypted {
			got, _ := loopback.tls_read(&link.conn, dst)
			if got > 0 {
				return got, false
			}
			return 0, true
		}
		got, err := net.recv_tcp(link.fd, dst)
		if err == .Interrupted {
			continue
		}
		if got > 0 {
			return got, false
		}
		return 0, true
	}
}

write_all :: proc(link: ^Link, payload: []u8) -> bool {
	rest := payload
	for len(rest) > 0 {
		if link.encrypted {
			return loopback.tls_write(&link.conn, rest)
		}
		n, err := net.send_tcp(link.fd, rest)
		if n > 0 {
			rest = rest[n:]
			continue
		}
		if err == .Interrupted {
			continue
		}
		return false
	}
	return true
}

must_write :: proc(link: ^Link, payload: []u8) {
	if !write_all(link, payload) {
		fail("write")
	}
}

fill_reader :: proc(rd: ^Reader) -> bool {
	if rd.r > 0 {
		copy(rd.buf[:], rd.buf[rd.r:rd.w])
		rd.w -= rd.r
		rd.r = 0
	}
	if rd.w >= len(rd.buf) {
		fail("reader fill")
	}
	n, bad := link_read(rd.link, rd.buf[rd.w:])
	rd.w += n
	if bad || n == 0 {
		rd.err = true
		return false
	}
	return true
}

// 16KiB reads match bufio.Reader. Bytes past the header line stay buffered
// and count as the first body bytes.
read_slice :: proc(rd: ^Reader) -> (line: []u8, kind: Read_Kind) {
	for {
		scanned := rd.buf[rd.r:rd.w]
		hit := -1
		for i in 0 ..< len(scanned) {
			if scanned[i] == '\n' {
				hit = i
				break
			}
		}
		if hit >= 0 {
			line = rd.buf[rd.r:][:hit + 1]
			rd.r += hit + 1
			return line, .Line
		}
		if rd.err {
			line = rd.buf[rd.r:rd.w]
			rd.r = rd.w
			return line, .Error
		}
		if rd.w - rd.r >= len(rd.buf) {
			line = rd.buf[rd.r:rd.w]
			rd.r = rd.w
			return line, .Full
		}
		if !fill_reader(rd) {
			continue
		}
	}
}

field_get :: proc(fields: []Field, name: string) -> (string, bool) {
	for field in fields {
		if strings.equal_fold(field.name, name) {
			return field.value, true
		}
	}
	return "", false
}

read_head :: proc(rd: ^Reader, storage: ^[dynamic]u8) -> Request {
	clear(storage)
	done := false
	for len(storage) <= MAX_HEADER {
		line, kind := read_slice(rd)
		append(storage, ..line)
		require(len(storage) <= MAX_HEADER, "request header bound")
		if kind == .Full {
			continue
		}
		if kind == .Error {
			fail("request header")
		}
		if len(storage) >= 4 && string(storage[len(storage) - 4:]) == "\r\n\r\n" {
			done = true
			break
		}
	}
	require(done, "request header bound")
	lines := strings.split(string(storage[:]), "\r\n")
	defer delete(lines)
	require(len(lines) >= 1, "request line")
	words := strings.split(lines[0], " ")
	defer delete(words)
	require(len(words) == 3 && words[2] == "HTTP/1.1", "request line")
	fields: [dynamic]Field
	defer delete(fields)
	for i in 1 ..< len(lines) {
		line := lines[i]
		if line == "" {
			continue
		}
		colon := strings.index(line, ":")
		require(colon >= 0, "request field")
		name := line[:colon]
		value := strings.trim_space(line[colon + 1:])
		for prev in fields {
			if strings.equal_fold(prev.name, name) {
				fail("duplicate request field")
			}
		}
		append(&fields, Field{name = name, value = value})
	}
	host, host_ok := field_get(fields[:], "host")
	require(host_ok && host != "", "Host absent")
	head: Request
	head.method = words[0]
	head.target = words[1]
	if value, ok := field_get(fields[:], "content-length"); ok {
		consumed: int
		n, parsed := strconv.parse_int(value, 10, &consumed)
		if !parsed || consumed != len(value) {
			fail("request body bound")
		}
		require(n >= 0 && n <= MAX_BODY, "request body bound")
		head.length = n
	}
	if value, ok := field_get(fields[:], "transfer-encoding"); ok {
		require(value == "", "unexpected upload coding")
	}
	if value, ok := field_get(fields[:], "accept-encoding"); ok {
		head.accept = value
	}
	if value, ok := field_get(fields[:], "authorization"); ok {
		head.authorization = value
	}
	return head
}

take :: proc(f: ^Fixture, link: ^Link, storage: ^[dynamic]u8) -> (Reader, Request) {
	rd := Reader{link = link}
	head := read_head(&rd, storage)
	f.requests += 1
	if len(head.accept) > len(f.accept_buf) {
		fail("accept-encoding")
	}
	f.accept_n = copy(f.accept_buf[:], head.accept)
	return rd, head
}

copy_n :: proc(rd: ^Reader, want: int, ctx: ^sha2.Context_256) -> (got: int, bad: bool) {
	if want == 0 {
		return 0, false
	}
	for got < want {
		if rd.r < rd.w {
			take_n := min(rd.w - rd.r, want - got)
			chunk := rd.buf[rd.r:][:take_n]
			if ctx != nil {
				sha2.update(ctx, chunk)
			}
			rd.r += take_n
			got += take_n
			continue
		}
		if rd.err {
			return got, true
		}
		rd.r = 0
		rd.w = 0
		n, failed := link_read(rd.link, rd.buf[:min(len(rd.buf), want - got)])
		if n > 0 {
			if ctx != nil {
				sha2.update(ctx, rd.buf[:n])
			}
			got += n
			if got >= want {
				return got, false
			}
			if failed {
				rd.err = true
				return got, true
			}
			continue
		}
		rd.err = true
		return got, true
	}
	return got, false
}

arm_io :: proc(fd: net.TCP_Socket, limit: time.Duration) {
	if net.set_option(fd, .TCP_Nodelay, true) != nil {
		fail("nodelay")
	}
	if net.set_option(fd, .Send_Timeout, limit) != nil || net.set_option(fd, .Receive_Timeout, limit) != nil {
		fail("deadline")
	}
}

tune_buffers :: proc(f: ^Fixture, fd: net.TCP_Socket) {
	if strings.has_prefix(f.mode, "early-final") || f.mode == "upload-stall" || f.mode == "upload-source-error-blocked" {
		if net.set_option(fd, .Receive_Buffer_Size, 4096) != nil {
			fail("read buffer")
		}
	}
	if f.mode == "credit" || f.mode == "cancel" || f.mode == "timeout" || f.mode == "fairness" {
		if net.set_option(fd, .Send_Buffer_Size, 4096) != nil {
			fail("write buffer")
		}
	}
}

bound_port :: proc(fd: net.TCP_Socket) -> int {
	endpoint, err := net.bound_endpoint(fd)
	if err != nil {
		fail("bound")
	}
	return endpoint.port
}

accept_link :: proc(f: ^Fixture, listener: net.TCP_Socket, encrypted: bool) -> Link {
	fd, _, err := net.accept_tcp(listener)
	if err != nil {
		fail("accept")
	}
	arm_io(fd, 15 * time.Second)
	tune_buffers(f, fd)
	link := Link {
		fd = fd,
		encrypted = encrypted,
		conn = {fd = fd},
	}
	if !encrypted {
		return link
	}
	if !loopback.handshake(&link.conn, .HTTP1) {
		reason := link.conn.reason
		net.close(fd)
		link.closed = true
		loopback.conn_wipe(&link.conn)
		fail(reason if reason != "" else "handshake")
	}
	loopback.set_recv_timeout(fd, 15 * time.Second)
	alpn := string(link.conn.alpn[:link.conn.alpn_n])
	if alpn != "http/1.1" {
		net.close(fd)
		link.closed = true
		loopback.conn_wipe(&link.conn)
		fail("actual ALPN")
	}
	f.alpn_n = copy(f.alpn[:], alpn)
	link.established = true
	return link
}

write_head :: proc(link: ^Link, status, length: int, fields: string) {
	buf: [2048]u8
	n := len(fmt.bprintf(buf[:], "HTTP/1.1 %d Fixture\r\n", status))
	if length >= 0 {
		n += len(fmt.bprintf(buf[n:], "Content-Length: %d\r\n", length))
	}
	if n + len(fields) + 2 > len(buf) {
		fail("response head")
	}
	n += copy(buf[n:], fields)
	buf[n] = '\r'
	buf[n + 1] = '\n'
	n += 2
	if !write_all(link, buf[:n]) {
		fail("response head")
	}
}

stream_pattern :: proc(f: ^Fixture, link: ^Link, size: int, chunked, fragmented: bool) -> bool {
	block: [SCRATCH]u8
	first := true
	at := 0
	for at < size {
		n := min(SCRATCH, size - at)
		if first && f.barrier {
			n = min(n, 1024)
		}
		pattern_at(block[:n], at)
		if chunked {
			hexb: [32]u8
			piece := fmt.bprintf(hexb[:], "%x\r\n", n)
			if !write_all(link, bytes_of(piece)) {
				return false
			}
		}
		if fragmented {
			for i in 0 ..< n {
				if !write_all(link, block[i:i + 1]) {
					return false
				}
			}
		} else if !write_all(link, block[:n]) {
			return false
		}
		if chunked {
			crlf := [2]u8{'\r', '\n'}
			if !write_all(link, crlf[:]) {
				return false
			}
		}
		at += n
		f.wire += n
		if first && f.barrier {
			marker(f, "first-written")
			wait_file(f, "first-taken")
			f.first_chunk_barrier = true
		}
		first = false
	}
	if chunked {
		return write_all(link, bytes_of("0\r\nX-Complete: yes\r\n\r\n"))
	}
	return true
}

with_header_crc :: proc(payload: [dynamic]u8) -> [dynamic]u8 {
	require(len(payload) >= 18 && payload[3] == 0, "plain gzip header required")
	header: [10]u8
	copy(header[:], payload[:10])
	header[3] = 2
	sum := hash.crc32(header[:])
	out: [dynamic]u8
	append(&out, ..header[:])
	append(&out, u8(sum), u8(sum >> 8))
	append(&out, ..payload[10:])
	delete(payload)
	return out
}

prepare_compressed :: proc(f: ^Fixture) {
	repeated := f.mode == "gzip-amplification"
	payload := gzip_payload(f.size, repeated, f.mode == "gzip-metadata")
	f.decoded = f.size
	if repeated {
		f.body_sha_n = digest_repeat(f.size, f.body_sha[:])
	} else {
		f.body_sha_n = digest_pattern(f.size, f.body_sha[:])
	}
	switch f.mode {
	case "gzip-crc", "gzip-crc-held":
		payload[len(payload) - 8] ~= 1
	case "gzip-size":
		payload[len(payload) - 4] ~= 1
	case "gzip-truncated":
		if resize(&payload, len(payload) - 1) != nil {
			fail("gzip")
		}
	case "gzip-trailing":
		append(&payload, 'x')
	case "gzip-members":
		extra := gzip_payload(31, false, false)
		append(&payload, ..extra[:])
		delete(extra)
	case "gzip-fhcrc", "gzip-fhcrc-invalid":
		payload = with_header_crc(payload)
		if f.mode == "gzip-fhcrc-invalid" {
			payload[10] ~= 1
		}
	}
	f.encoded = payload
	f.wire = len(payload)
	if f.mode == "buffered-gzip" {
		f.body_sha_n = digest_bytes(f.encoded[:], f.body_sha[:])
	}
	num: [32]u8
	text := fmt.bprintf(num[:], "%d", len(payload))
	path: [4096]u8
	p := join_path(path[:], f.directory, "encoded-length")
	if os.write_entire_file(p, text, FILE_PERM) != nil {
		fail("encoded-length")
	}
}

compressed :: proc(f: ^Fixture, link: ^Link) {
	require(f.encoded != nil, "prepared gzip vector")
	chunked := f.mode == "gzip-chunked"
	eof := f.mode == "gzip-eof"
	fields := "Content-Encoding: gzip\r\nConnection: close\r\n"
	if chunked {
		fields = "Content-Encoding: gzip\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n"
	}
	length := len(f.encoded)
	if chunked || eof {
		length = -1
	}
	write_head(link, 200, length, fields)
	payload := f.encoded[:]
	if chunked {
		at := 0
		for at < len(payload) {
			n := min(137, len(payload) - at)
			hexb: [32]u8
			piece := fmt.bprintf(hexb[:], "%x\r\n", n)
			must_write(link, bytes_of(piece))
			must_write(link, payload[at:][:n])
			crlf := [2]u8{'\r', '\n'}
			must_write(link, crlf[:])
			at += n
		}
		must_write(link, bytes_of("0\r\n\r\n"))
	} else if f.mode == "gzip-fragmented" {
		for i in 0 ..< len(payload) {
			must_write(link, payload[i:i + 1])
		}
	} else {
		_ = write_all(link, payload)
	}
}

respond :: proc(f: ^Fixture, link: ^Link) {
	if strings.has_prefix(f.mode, "gzip") || f.mode == "buffered-gzip" {
		compressed(f, link)
		return
	}
	f.decoded = f.size
	require(f.body_sha_n == 64, "expected response digest prepared before readiness")
	switch f.mode {
	case "head-gzip", "no-content-gzip", "not-modified-gzip":
		status := 200
		if f.mode == "no-content-gzip" {
			status = 204
		}
		if f.mode == "not-modified-gzip" {
			status = 304
		}
		write_head(link, status, f.size, "Content-Encoding: gzip\r\nConnection: close\r\n")
		f.decoded = 0
		f.wire = 0
		f.body_sha_n = digest_bytes(nil, f.body_sha[:])
	case "coding-unsupported", "coding-chain", "coding-repeated":
		fields := "Content-Encoding: br\r\nConnection: close\r\n"
		if f.mode == "coding-chain" {
			fields = "Content-Encoding: gzip, gzip\r\nConnection: close\r\n"
		}
		if f.mode == "coding-repeated" {
			fields = "Content-Encoding: gzip\r\nContent-Encoding: gzip\r\nConnection: close\r\n"
		}
		write_head(link, 200, 3, fields)
		_ = write_all(link, bytes_of("bad"))
	case "chunk-invalid-size":
		write_head(link, 200, -1, "Transfer-Encoding: chunked\r\nConnection: close\r\n")
		must_write(link, bytes_of("z\r\n"))
	case "chunk-invalid-crlf":
		write_head(link, 200, -1, "Transfer-Encoding: chunked\r\nConnection: close\r\n")
		must_write(link, bytes_of("3\r\nabcXX0\r\n\r\n"))
	case "chunk-truncated":
		write_head(link, 200, -1, "Transfer-Encoding: chunked\r\nConnection: close\r\n")
		must_write(link, bytes_of("800\r\npartial"))
	case "chunk-missing-terminal":
		write_head(link, 200, -1, "Transfer-Encoding: chunked\r\nConnection: close\r\n")
		must_write(link, bytes_of("3\r\nabc\r\n"))
	case "chunk-trailer-invalid":
		write_head(link, 200, -1, "Transfer-Encoding: chunked\r\nConnection: close\r\n")
		must_write(link, bytes_of("0\r\nnot-a-field\r\n\r\n"))
	case "conflicting-framing":
		write_head(link, 200, 3, "Transfer-Encoding: chunked\r\nConnection: close\r\n")
		must_write(link, bytes_of("0\r\n\r\n"))
	case:
		chunked := f.mode == "chunked"
		eof := f.mode == "eof"
		fields := "Connection: close\r\n"
		length := f.size
		if chunked {
			fields = "Connection: close\r\nTransfer-Encoding: chunked\r\n"
			length = -1
		} else if eof {
			length = -1
		}
		write_head(link, 200, length, fields)
		size := f.size
		if f.mode == "short-length" || f.mode == "buffered-short" {
			size /= 2
		}
		ok := stream_pattern(f, link, size, chunked, f.mode == "fragmented")
		if f.mode == "timeout" || f.mode == "cancel" {
			require(!ok, "held output peer unexpectedly completed entire response")
			marker(f, "transport-retired")
		}
		if f.mode != "credit" && f.mode != "cancel" && f.mode != "timeout" && f.mode != "encoded-limit" && f.mode != "decoded-limit" {
			if !ok {
				fail("response body")
			}
		}
	}
}

upload :: proc(f: ^Fixture, link: ^Link, rd: ^Reader, head: Request) {
	require(head.method == "POST", "upload method")
	if f.mode == "upload-source-error-blocked" {
		marker(f, "head-received")
		wait_file(f, "upload-blocked")
		wait_file(f, "native-failed")
		ctx: sha2.Context_256
		sha2.init_256(&ctx)
		n, bad := copy_n(rd, head.length, &ctx)
		f.upload_bytes = n
		f.upload_sha_n = finish_sha(&ctx, f.upload_sha[:])
		require(bad && n < head.length, "source-error request transmitted full upload")
		return
	}
	if strings.has_prefix(f.mode, "early-final") {
		if f.mode == "early-final-blocked" {
			marker(f, "head-received")
			wait_file(f, "upload-blocked")
		}
		if f.mode != "early-final" {
			n, bad := copy_n(rd, min(head.length, 64 * 1024), nil)
			if bad {
				fail("early final")
			}
			f.upload_bytes = n
		}
		f.early_final = true
		write_head(link, 413, 3, "Connection: close\r\n")
		must_write(link, bytes_of("no!"))
		marker(f, "final-written")
		remaining := head.length - f.upload_bytes
		limit := remaining
		if limit > 4 << 20 {
			limit = 4 << 20
		}
		if limit > 0 {
			n, bad := copy_n(rd, limit, nil)
			f.upload_bytes += n
			require(bad, "upload continued through drain cap after early final")
		}
		return
	}
	if f.mode == "upload-stall" {
		marker(f, "head-received")
		wait_file(f, "release-peer")
		return
	}
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	n, bad := copy_n(rd, head.length, &ctx)
	f.upload_bytes = n
	f.upload_sha_n = finish_sha(&ctx, f.upload_sha[:])
	f.upload_complete = !bad && n == head.length
	if f.mode == "upload-short" || f.mode == "upload-cancel" || f.mode == "upload-source-error" || f.mode == "upload-overrun" {
		require(bad, "abandoned upload completed")
		return
	}
	if bad {
		fail("upload")
	}
	expect: [64]u8
	expect_n := digest_pattern(head.length, expect[:])
	require(string(f.upload_sha[:f.upload_sha_n]) == string(expect[:expect_n]), "upload byte identity")
	write_head(link, 200, 2, "Connection: close\r\n")
	must_write(link, bytes_of("ok"))
}

// poll, because a receive timeout does not wake accept on Darwin.
await_quiet :: proc(listener: net.TCP_Socket, limit: time.Duration, hit, observe: string) {
	deadline := time.time_add(time.now(), limit)
	for {
		remain := time.diff(time.now(), deadline)
		if remain <= 0 {
			return
		}
		ms := i64(time.duration_milliseconds(remain))
		if ms < 1 {
			ms = 1
		}
		pfd := posix.pollfd {
			fd = posix.FD(c.int(i64(listener))),
			events = {.IN},
		}
		rc := posix.poll(&pfd, posix.nfds_t(1), c.int(ms))
		if rc == 0 {
			return
		}
		if rc < 0 {
			if posix.errno() == .EINTR {
				continue
			}
			fail(observe)
		}
		fd, _, err := net.accept_tcp(listener)
		if err == .Interrupted || err == .Would_Block {
			continue
		}
		if err != nil {
			fail(observe)
		}
		net.close(fd)
		fail(hit)
	}
}

redirects :: proc(f: ^Fixture) {
	final_listener := f.listener
	final_encrypted := f.encrypted
	extra: Closer
	defer close_closer(&extra)
	if strings.has_prefix(f.mode, "redirect-cross") || f.mode == "redirect-downgrade" {
		sock, err := net.listen_tcp({address = net.IP4_Loopback, port = 0})
		if err != nil {
			fail("listen")
		}
		extra.fd = sock
		extra.open = true
		final_listener = extra.fd
		if f.mode == "redirect-downgrade" {
			final_encrypted = false
		}
	}
	scheme := "http"
	if final_encrypted {
		scheme = "https"
	}
	loc: [512]u8
	fields := fmt.bprintf(loc[:], "Location: %s://127.0.0.1:%d/final\r\nX-Intermediate: hidden\r\nConnection: close\r\n", scheme, bound_port(final_listener))
	first := accept_link(f, f.listener, f.encrypted)
	defer close_link(&first)
	storage: [dynamic]u8
	defer delete(storage)
	_, head := take(f, &first, &storage)
	require(head.length == 0 && head.target == "/start", "initial redirect request")
	if f.mode == "redirect-cross-auth" {
		require(head.authorization == "Bearer owned-fixture", "initial authorization")
	}
	if f.mode == "redirect-deadline" {
		time.sleep(150 * time.Millisecond)
	}
	if f.mode == "redirect-malformed" {
		write_head(&first, 302, 16, fields)
		must_write(&first, bytes_of("bad"))
		close_link(&first)
		f.intermediate_sent = true
		return
	}
	if f.mode == "redirect-gzip-invalid" {
		payload := gzip_payload(31, false, false)
		defer delete(payload)
		payload[len(payload) - 8] ~= 1
		extra_fields: [640]u8
		gzip_fields := fmt.bprintf(extra_fields[:], "%sContent-Encoding: gzip\r\n", fields)
		write_head(&first, 302, len(payload), gzip_fields)
		must_write(&first, payload[:])
		close_link(&first)
		f.intermediate_sent = true
		return
	}
	write_head(&first, 302, 4, fields)
	must_write(&first, bytes_of("skip"))
	close_link(&first)
	f.intermediate_sent = true
	marker(f, "intermediate-written")
	if f.mode == "redirect" || f.mode == "redirect-cross" {
		wait_file(f, "intermediate-hidden")
	}
	if f.mode == "redirect-cross-auth" {
		await_quiet(final_listener, 300 * time.Millisecond, "unsafe credentials contacted second origin", "cross-origin rejection observation")
		f.authorization_gone = true
		return
	}
	if f.mode == "redirect-downgrade" {
		await_quiet(final_listener, 300 * time.Millisecond, "HTTPS downgrade contacted HTTP peer", "downgrade observation")
		return
	}
	if f.mode == "redirect-loop" {
		for _ in 0 ..< 2 {
			conn := accept_link(f, f.listener, f.encrypted)
			clear(&storage)
			_, next := take(f, &conn, &storage)
			require(next.length == 0, "loop redirect body")
			write_head(&conn, 302, 0, fields)
			close_link(&conn)
		}
		return
	}
	last: Link
	defer close_link(&last)
	if f.mode == "redirect-deadline" && final_encrypted {
		raw, _, err := net.accept_tcp(final_listener)
		if err != nil {
			fail("accept")
		}
		arm_io(raw, 5 * time.Second)
		last = Link {
			fd = raw,
			encrypted = true,
			conn = {fd = raw},
		}
		if !loopback.handshake(&last.conn, .HTTP1) {
			f.deadline_handshake_abort = true
			net.close(raw)
			last.closed = true
			loopback.conn_wipe(&last.conn)
			return
		}
		loopback.set_recv_timeout(raw, 5 * time.Second)
		if string(last.conn.alpn[:last.conn.alpn_n]) != "http/1.1" {
			fail("deadline hop ALPN")
		}
		last.established = true
	} else {
		last = accept_link(f, final_listener, final_encrypted)
	}
	clear(&storage)
	_, next := take(f, &last, &storage)
	require(next.target == "/final" && next.length == 0, "followed request")
	if f.mode == "redirect-cross" {
		require(next.authorization == "", "cross-origin credentials leaked")
		f.authorization_gone = true
	}
	if f.mode == "redirect-deadline" {
		time.sleep(150 * time.Millisecond)
		_ = write_all(&last, bytes_of("HTTP/1.1 200 Fixture\r\nContent-Length: 2\r\nConnection: close\r\n\r\n"))
	} else {
		write_head(&last, 200, 2, "X-Final: yes\r\nConnection: close\r\n")
	}
	_ = write_all(&last, bytes_of("ok"))
	f.decoded = 2
	f.wire = 2
	f.body_sha_n = digest_bytes(bytes_of("ok"), f.body_sha[:])
}

serve_cheap :: proc(job: ^Cheap_Job) {
	fd, _, err := net.accept_tcp(job.listener)
	if err != nil {
		fail("cheap accept")
	}
	link := Link{fd = fd}
	defer close_link(&link)
	arm_io(fd, 5 * time.Second)
	storage: [dynamic]u8
	defer delete(storage)
	rd := Reader{link = &link}
	head := read_head(&rd, &storage)
	if head.target != "/cheap" || head.length != 0 {
		fail("cheap request")
	}
	path: [4096]u8
	retired := join_path(path[:], job.directory, "transport-retired")
	if os.exists(retired) {
		fail("cheap request waited for held transport retirement")
	}
	if !write_all(&link, bytes_of("HTTP/1.1 200 Fixture\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")) {
		fail("cheap write")
	}
	job.ok = true
}

fairness :: proc(f: ^Fixture) {
	cheap, err := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if err != nil {
		fail("listen")
	}
	held := Closer {
		fd = cheap,
		open = true,
	}
	defer close_closer(&held)
	path: [4096]u8
	p := join_path(path[:], f.directory, "cheap-endpoint")
	addr: [64]u8
	text := fmt.bprintf(addr[:], "127.0.0.1:%d", bound_port(cheap))
	if os.write_entire_file(p, text, FILE_PERM) != nil {
		fail("cheap endpoint")
	}
	job := new(Cheap_Job)
	job.listener = cheap
	job.directory = f.directory
	worker := thread.create_and_start_with_poly_data(job, serve_cheap)
	if worker == nil {
		fail("cheap thread")
	}
	line: [64]u8
	emit_line(fmt.bprintf(line[:], "127.0.0.1:%d", bound_port(f.listener)))
	link := accept_link(f, f.listener, f.encrypted)
	defer close_link(&link)
	storage: [dynamic]u8
	defer delete(storage)
	_, head := take(f, &link, &storage)
	require(head.length == 0, "held response request")
	write_head(&link, 200, f.size, "Connection: close\r\n")
	ok := stream_pattern(f, &link, f.size, false, false)
	require(!ok, "held stream unexpectedly completed entire body")
	marker(f, "transport-retired")
	thread.destroy(worker)
	f.cheap_before_release = job.ok
	free(job)
	f.requests += 1
}

quote_json :: proc(dst: []u8, s: string) -> string {
	n := 0
	put := proc(dst: []u8, n: ^int, c: u8) {
		if n^ >= len(dst) {
			fail("json")
		}
		dst[n^] = c
		n^ += 1
	}
	put(dst, &n, '"')
	for i in 0 ..< len(s) {
		c := s[i]
		if n + 8 >= len(dst) {
			fail("json")
		}
		if c == '"' || c == '\\' {
			put(dst, &n, '\\')
			put(dst, &n, c)
		} else if c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t' {
			esc: u8 = 'b'
			if c == '\f' {
				esc = 'f'
			} else if c == '\n' {
				esc = 'n'
			} else if c == '\r' {
				esc = 'r'
			} else if c == '\t' {
				esc = 't'
			}
			put(dst, &n, '\\')
			put(dst, &n, esc)
		} else if c < 0x20 || c == '&' || c == '<' || c == '>' {
			put(dst, &n, '\\')
			put(dst, &n, 'u')
			put(dst, &n, '0')
			put(dst, &n, '0')
			put(dst, &n, hex_digits[int(c >> 4)])
			put(dst, &n, hex_digits[int(c & 15)])
		} else {
			put(dst, &n, c)
		}
	}
	put(dst, &n, '"')
	return string(dst[:n])
}

bool_text :: proc(v: bool) -> string {
	if v {
		return "true"
	}
	return "false"
}

emit_line :: proc(text: string) {
	if _, err := os.write(os.stdout, bytes_of(text)); err != nil {
		fail("stdout")
	}
	nl := [1]u8{'\n'}
	if _, err := os.write(os.stdout, nl[:]); err != nil {
		fail("stdout")
	}
	// os.write is unbuffered. flush is fsync, which a pipe rejects on Darwin.
	_ = os.flush(os.stdout)
}

emit_json :: proc(f: ^Fixture) {
	mode_q: [192]u8
	alpn_q: [96]u8
	body_q: [160]u8
	upload_q: [160]u8
	accept_q: [6144]u8
	qmode := quote_json(mode_q[:], f.mode)
	qalpn := quote_json(alpn_q[:], string(f.alpn[:f.alpn_n]))
	qbody := quote_json(body_q[:], string(f.body_sha[:f.body_sha_n]))
	qupload := quote_json(upload_q[:], string(f.upload_sha[:f.upload_sha_n]))
	qaccept := quote_json(accept_q[:], string(f.accept_buf[:f.accept_n]))
	buf: [8192]u8
	text := fmt.bprintf(
		buf[:],
		"{{\"mode\":%s,\"tls\":%s,\"alpn\":%s,\"requests\":%d,\"wire_body_bytes\":%d,\"decoded_body_bytes\":%d,\"body_sha256\":%s,\"upload_bytes\":%d,\"upload_sha256\":%s,\"upload_complete\":%s,\"accept_encoding\":%s,\"first_chunk_barrier\":%s,\"early_final\":%s,\"authorization_gone\":%s,\"intermediate_sent\":%s,\"cheap_before_release\":%s,\"deadline_handshake_abort\":%s}}",
		qmode,
		bool_text(f.encrypted),
		qalpn,
		f.requests,
		f.wire,
		f.decoded,
		qbody,
		f.upload_bytes,
		qupload,
		bool_text(f.upload_complete),
		qaccept,
		bool_text(f.first_chunk_barrier),
		bool_text(f.early_final),
		bool_text(f.authorization_gone),
		bool_text(f.intermediate_sent),
		bool_text(f.cheap_before_release),
		bool_text(f.deadline_handshake_abort),
	)
	emit_line(text)
}

parse_bool :: proc(value: string) -> (on, known: bool) {
	switch value {
	case "1", "t", "T", "true", "TRUE", "True":
		return true, true
	case "0", "f", "F", "false", "FALSE", "False":
		return false, true
	}
	return false, false
}

parse_flags :: proc(mode, directory: ^string, size: ^int, encrypted, barrier: ^bool) {
	mode^ = "known"
	size^ = 32 << 20
	i := 1
	for i < len(os.args) {
		arg := os.args[i]
		if len(arg) < 2 || arg[0] != '-' {
			fail("fixture options")
		}
		name := arg[1:]
		if len(name) > 0 && name[0] == '-' {
			name = name[1:]
		}
		value := ""
		has := false
		if eq := strings.index(name, "="); eq >= 0 {
			value = name[eq + 1:]
			name = name[:eq]
			has = true
		}
		switch name {
		case "mode", "dir", "bytes":
			if !has {
				i += 1
				if i >= len(os.args) {
					fail("fixture options")
				}
				value = os.args[i]
			}
			switch name {
			case "mode":
				mode^ = value
			case "dir":
				directory^ = value
			case "bytes":
				consumed: int
				n, parsed := strconv.parse_int(value, 10, &consumed)
				if !parsed || consumed != len(value) {
					fail("fixture options")
				}
				size^ = n
			}
		case "tls", "first-chunk-barrier":
			on := true
			if has {
				known: bool
				on, known = parse_bool(value)
				if !known {
					fail("fixture options")
				}
			}
			if name == "tls" {
				encrypted^ = on
			} else {
				barrier^ = on
			}
		case:
			fail("fixture options")
		}
		i += 1
	}
	if directory^ == "" || size^ < 0 || size^ > MAX_BODY {
		fail("fixture options")
	}
}

read_one :: proc(link: ^Link, dst: []u8) -> int {
	n, _ := link_read(link, dst)
	return n
}

main :: proc() {
	_ = posix.signal(.SIGPIPE, auto_cast posix.SIG_IGN)
	mode: string
	directory: string
	size: int
	encrypted := false
	barrier := false
	parse_flags(&mode, &directory, &size, &encrypted, &barrier)
	if err := os.make_directory_all(directory, DIR_PERM); err != nil && err != .Exist {
		fail("directory")
	}
	listener, listen_err := net.listen_tcp({address = net.IP4_Loopback, port = 0})
	if listen_err != nil {
		fail("listen")
	}
	f := Fixture {
		mode = mode,
		directory = directory,
		size = size,
		encrypted = encrypted,
		barrier = barrier,
		listener = listener,
	}
	defer net.close(f.listener)
	defer free_tables()
	defer delete_encoded(&f)
	defer loopback.identity_clear()
	if encrypted {
		dns := [?]string{"localhost"}
		raw := [4]u8{127, 0, 0, 1}
		ips := [?][]u8{raw[:]}
		root: [4096]u8
		cert := join_path(root[:], directory, "root.pem")
		if !loopback.mint_p256(cert, "localhost", dns[:], ips[:]) {
			fail("certificate")
		}
	}
	if strings.has_prefix(f.mode, "gzip") || f.mode == "buffered-gzip" {
		prepare_compressed(&f)
	} else if !strings.has_prefix(f.mode, "upload") &&
	   !strings.has_prefix(f.mode, "early-final") &&
	   !strings.has_prefix(f.mode, "redirect") &&
	   f.mode != "fairness" &&
	   !strings.has_prefix(f.mode, "allocation-") {
		f.body_sha_n = digest_pattern(f.size, f.body_sha[:])
	}
	if f.mode == "fairness" {
		fairness(&f)
		emit_json(&f)
		return
	}
	line: [64]u8
	emit_line(fmt.bprintf(line[:], "127.0.0.1:%d", bound_port(f.listener)))
	if strings.has_prefix(f.mode, "redirect") {
		redirects(&f)
		emit_json(&f)
		return
	}
	if f.mode == "allocation-engine" {
		await_quiet(f.listener, time.Second, "failed engine connected", "engine observation")
		emit_json(&f)
		return
	}
	link := accept_link(&f, f.listener, f.encrypted)
	defer close_link(&link)
	storage: [dynamic]u8
	defer delete(storage)
	rd, head := take(&f, &link, &storage)
	if f.mode == "allocation-head-fields" {
		marker(&f, "allocation-ready")
		wait_file(&f, "allocation-release")
		write_head(&link, 200, 2, "X-Fault-Point: descriptors\r\nConnection: close\r\n")
		_ = write_all(&link, bytes_of("ok"))
		emit_json(&f)
		return
	}
	if strings.has_prefix(f.mode, "upload") || strings.has_prefix(f.mode, "early-final") {
		upload(&f, &link, &rd, head)
	} else {
		require(head.length == 0, "response-only request body")
		respond(&f, &link)
	}
	emit_json(&f)
}

