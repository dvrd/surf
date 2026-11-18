package surf_exchange

import channel "../stream"
import h1 "../../../http/v1"
import "core:compress/deflate"
import "core:mem/owned"
import "core:testing"

@(test)
stream_gzip_footer_finishes_while_last_chunk_held :: proc(t: ^testing.T) {
	bank, bank_error := channel.bank_create(
		{
			streams = 1,
			response_chunks = 1,
			upload_chunks = 1,
			max_chunk_bytes = 16,
			max_retained_bytes_per_stream = 32,
		},
		context.allocator,
	)
	testing.expect_value(t, bank_error.kind, .None)

	if bank_error.kind != .None {
		return
	}

	defer channel.bank_close(&bank)
	cell, cell_error := channel.channel_create(bank, {decoding = .Gzip})
	testing.expect_value(t, cell_error.kind, .None)

	if cell_error.kind != .None {
		return
	}

	defer channel.release_request(cell)
	x: Stream_Exchange
	testing.expect_value(t, exchange_init(&x.base, {}, context.allocator).kind, .None)
	x.channel = cell
	x.tx = .Done
	x.decoded = true
	x.entity_done = true
	x.base._phase = .Reading_Body
	x.base._head.framing = .Length
	// Independent Python gzip encoding of the single byte "x". The raw payload
	// is already delivered; only checksum/ISIZE validation remains at this seam.
	wire := [21]u8{31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 171, 0, 0, 131, 22, 220, 140, 1, 0, 0, 0}
	testing.expect_value(t, deflate.inflate_gzip_decoder_init(&x.decoder), .None)
	slot, output := channel.reserve_output(cell)
	decoded := deflate.inflate_gzip_decoder_step(&x.decoder, wire[:13], output, false)
	testing.expect(t, decoded.err == .None && decoded.consumed == 13 && decoded.produced == 1)
	testing.expect(t, channel.publish_output(slot, decoded.produced))
	held: owned.Chunk
	status, error := channel.next(cell, &held)
	testing.expect(t, status == .Chunk && error.kind == .None)
	defer owned.destroy(&held)
	testing.expect_value(t, string(held.data), "x")
	copy(x.encoded[:], wire[13:])
	x.encoded_used = 8
	finished := false

	for _ in 0 ..< 8 {
		result := stream_exchange_drive(&x, 1, false, 64)
		testing.expect_value(t, result.error.kind, .None)

		if result.status == .Done {
			finished = true
			break
		}
	}

	testing.expect(t, finished, "Footer validation must not require another output slot")
	testing.expect_value(t, string(held.data), "x")
}

@(test)
stream_identity_terminal_framing_finishes_while_last_chunk_held :: proc(t: ^testing.T) {
	for chunked in ([2]bool{false, true}) {
		bank, bank_error := channel.bank_create(
			{
				streams = 1,
				response_chunks = 1,
				upload_chunks = 1,
				max_chunk_bytes = 16,
				max_retained_bytes_per_stream = 32,
			},
			context.allocator,
		)
		assert(bank_error.kind == .None)
		defer channel.bank_close(&bank)
		cell, cell_error := channel.channel_create(bank, {})
		assert(cell_error.kind == .None)
		defer channel.release_request(cell)
		x: Stream_Exchange
		assert(exchange_init(&x.base, {}, context.allocator).kind == .None)
		x.channel = cell
		x.tx = .Done
		x.base._phase = .Reading_Body

		if chunked {
			x.base._head.framing = .Chunked
			assert(h1.chunk_decoder_init(&x.base._chunk, 100).kind == .None)
			x.base._read_used = copy(x.base._read_buffer[:], transmute([]u8)string("0\r\nX-Note: end\r\n\r\n"))
		} else {
			x.base._head.framing = .EOF
			x.base._read.ready = true
			x.base._read.result.err.kind = .Peer_Closed
		}

		slot, output := channel.reserve_output(cell)
		output[0] = 'x'
		assert(channel.publish_output(slot, 1))
		held: owned.Chunk
		status, error := channel.next(cell, &held)
		assert(status == .Chunk && error.kind == .None)
		defer owned.destroy(&held)
		finished := false

		for _ in 0 ..< 8 {
			result := stream_exchange_drive(&x, 1, false, 64)
			testing.expect_value(t, result.error.kind, .None)

			if result.status == .Done {
				finished = true
				break
			}
		}

		testing.expect(t, finished, "Chunk terminator/EOF must not require another output slot")
		testing.expect_value(t, string(held.data), "x")
	}
}
