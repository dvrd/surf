package surf_stream

import http "shared:http"
import "core:mem/owned"
import "core:sync"
import surf "../.."
import signal "shared:async/signal"
import "core:mem"
import charged "core:mem/budget"
import scopes "core:sync/budget"
import "core:io"

range_overlap :: proc(a: rawptr, an: int, b: rawptr, bn: int) -> bool {
	if an <= 0 || bn <= 0 {
		return false
	}

	av, bv := uintptr(a), uintptr(b)

	return av <= bv && bv - av < uintptr(an) || bv < av && av - bv < uintptr(bn)
}

aliases :: proc(cell: ^Channel, destination: rawptr, size: int) -> bool {
	bank := cell.bank
	if range_overlap(destination, size, cell, size_of(Channel)) ||
	   range_overlap(destination, size, bank, size_of(Bank)) ||
	   range_overlap(destination, size, raw_data(bank.cells), len(bank.cells) * size_of(Cell_Entry)) ||
	   range_overlap(destination, size, raw_data(cell.output_storage), len(cell.output_storage)) {
		return true
	}

	sync.lock(&cell.mu)
	defer sync.unlock(&cell.mu)
	if range_overlap(destination, size, raw_data(cell.head.header_storage), len(cell.head.header_storage)) ||
	   range_overlap(destination, size, raw_data(cell.head.headers), len(cell.head.headers) * size_of(http.Header)) {
		return true
	}

	for chunk in cell.uploads {
		if range_overlap(destination, size, raw_data(chunk.storage), len(chunk.storage)) {
			return true
		}
	}

	return false
}

chunk_empty :: proc(chunk: ^owned.Chunk) -> bool {
	return(
		chunk != nil &&
		chunk.release == nil &&
		chunk.allocator.procedure == nil &&
		raw_data(chunk.data) == nil &&
		raw_data(chunk.storage) == nil &&
		chunk.user_data == nil &&
		chunk.allocator.data == nil \
	)
}

allocation_error :: proc(cause: mem.Allocator_Error) -> Error {
	return {kind = .Allocation_Failed, http = {kind = .Allocation_Failed, allocation = cause}}
}

bank_create :: proc(input: Limits, allocator: mem.Allocator) -> (^Bank, Error) {
	limits, valid := limits_normalize(input, MAX_STREAMS)

	if !valid || allocator.procedure == nil {
		return nil, {kind = .Invalid}
	}

	binding: charged.Binding

	if charged.is_managed_allocator(allocator) {
		retained, error := charged.retain_allocator(allocator)

		if error.kind != .None {
			return nil, allocation_error(error.allocation)
		}

		binding = retained
	}

	bank, cause := create_value(Bank, allocator)

	if cause != nil {
		charged.release(&binding)
		return nil, allocation_error(cause)
	}

	bank^ = {
		references = 1,
		limits     = limits,
		allocator  = allocator,
		binding    = binding,
	}

	cells, error := create_array(Cell_Entry, limits.streams, allocator)

	if error != nil {
		free(bank, allocator)
		charged.release(&binding)
		return nil, allocation_error(error)
	}

	bank.cells = cells

	return bank, {}
}

bank_drop :: proc(bank: ^Bank) {
	sync.lock(&bank.mu)
	assert(bank.references > 0)
	bank.references -= 1
	last := bank.references == 0
	sync.unlock(&bank.mu)

	if !last {
		return
	}

	cells, allocator, binding := bank.cells, bank.allocator, bank.binding
	delete(cells, allocator)
	free(bank, allocator)
	charged.release(&binding)
}

bank_close :: proc(owner: ^^Bank) {
	if owner == nil || owner^ == nil {
		return
	}

	bank := owner^
	owner^ = nil
	sync.lock(&bank.mu)
	bank.closed = true
	sync.unlock(&bank.mu)
	bank_drop(bank)
}

channel_create :: proc(bank: ^Bank, input: Options) -> (^Channel, Error) {
	if bank == nil {
		return nil, {kind = .Invalid}
	}

	options, valid := options_normalize(input, 8 << 20)

	if !valid {
		return nil, {kind = .Invalid}
	}

	sync.lock(&bank.mu)
	index := -1

	if !bank.closed {
		for &entry, i in bank.cells {
			if !entry.reserved {
				entry.reserved = true
				index = i
				bank.references += 1
				break
			}
		}
	}

	closed := bank.closed
	sync.unlock(&bank.mu)

	if index < 0 {
		return nil, {kind = .Closed if closed else .Capacity}
	}

	allocator := bank.allocator
	cell, cause := create_value(Channel, allocator)

	if cause != nil {
		bank_unclaim(bank, index)
		return nil, allocation_error(cause)
	}

	cell^ = {
		bank        = bank,
		index       = index,
		references  = 1,
		claimed     = true,
		options     = options,
		wire_length = -1,
	}

	storage, error := create_array(u8, bank.limits.response_chunks * bank.limits.max_chunk_bytes, allocator)

	if error != nil {
		free(cell, allocator)
		bank_unclaim(bank, index)
		return nil, allocation_error(error)
	}

	cell.output_storage = storage

	for i in 0 ..< bank.limits.response_chunks {
		start := i * bank.limits.max_chunk_bytes
		cell.outputs[i] = {
			channel = cell,
			storage = storage[start:start + bank.limits.max_chunk_bytes],
		}
	}

	sync.lock(&bank.mu)
	bank.cells[index].channel = cell
	closed = bank.closed
	sync.unlock(&bank.mu)

	if closed {
		release(cell)
		return nil, {kind = .Closed}
	}

	return cell, {}
}

bank_unclaim :: proc(bank: ^Bank, index: int) {
	sync.lock(&bank.mu)
	bank.cells[index] = {}
	sync.unlock(&bank.mu)
	bank_drop(bank)
}

retain :: proc(cell: ^Channel) -> bool {
	if cell == nil {
		return false
	}

	sync.lock(&cell.mu)
	defer sync.unlock(&cell.mu)

	if cell.references < 1 || cell.references == max(int) {
		return false
	}

	cell.references += 1

	return true
}

// No allocator, application destructor or Signal wake runs under these locks.
release :: proc(cell: ^Channel) {
	if cell == nil {
		return
	}

	sync.lock(&cell.mu)
	assert(cell.references > 0)
	cell.references -= 1
	last := cell.references == 0

	if last {
		cell.returning = true
	}

	sync.unlock(&cell.mu)

	if !last {
		return
	}

	bank, index, lease := cell.bank, cell.index, cell.lease
	sync.lock(&bank.mu)
	bank.cells[index].channel = nil
	bank.cells[index].returning = true
	sync.unlock(&bank.mu)
	notification := cell.wake
	signal.release(&notification)

	for &chunk in cell.uploads {
		owned.destroy(&chunk)
	}

	surf.response_destroy(&cell.head)
	delete(cell.output_storage, bank.allocator)
	free(cell, bank.allocator)
	bank_unclaim(bank, index)
	scopes.release(&lease)
}

adopt_lease :: proc(cell: ^Channel, source: ^scopes.Lease) {
	sync.lock(&cell.mu)
	cell.lease = source^
	source^ = {}
	sync.unlock(&cell.mu)
}

set_notify :: proc(cell: ^Channel, source: signal.Signal) {
	next, _ := signal.retain(source)
	sync.lock(&cell.mu)
	previous := cell.wake
	cell.wake = next
	sync.unlock(&cell.mu)
	signal.release(&previous)
}

notify :: proc(cell: ^Channel) {
	sync.lock(&cell.mu)
	wake, _ := signal.retain(cell.wake)
	sync.unlock(&cell.mu)
	_ = signal.wake(wake)
	signal.release(&wake)
}

create_array :: proc($T: typeid, count: int, allocator: mem.Allocator) -> ([]T, mem.Allocator_Error) {
	if count < 0 || count > max(int) / size_of(T) {
		return nil, .Out_Of_Memory
	}

	size := count * size_of(T)
	storage, cause := allocator.procedure(allocator.data, .Alloc, size, align_of(T), nil, 0)
	if cause != nil ||
	   len(storage) != size ||
	   (size > 0 && raw_data(storage) == nil) ||
	   uintptr(raw_data(storage)) % uintptr(align_of(T)) != 0 {
		if raw_data(storage) != nil {
			_, _ = allocator.procedure(allocator.data, .Free, 0, align_of(T), raw_data(storage), len(storage))
		}
		return nil, .Out_Of_Memory if cause == nil else cause
	}

	for &value in storage {
		value = 0
	}

	return (cast([^]T)raw_data(storage))[:count], nil
}

create_value :: proc($T: typeid, allocator: mem.Allocator) -> (^T, mem.Allocator_Error) {
	storage, error := create_array(T, 1, allocator)

	if error != nil {
		return nil, error
	}

	return &storage[0], nil
}

reserve_output :: proc(cell: ^Channel) -> (^Output, []u8) {
	sync.lock(&cell.mu)
	defer sync.unlock(&cell.mu)

	if cell.closed {
		return nil, nil
	}

	for &slot in cell.outputs[:cell.bank.limits.response_chunks] {
		if slot.state == .Free {
			slot.state = .Filling
			return &slot, slot.storage
		}
	}

	return nil, nil
}

publish_output :: proc(slot: ^Output, count: int) -> bool {
	cell := slot.channel
	sync.lock(&cell.mu)
	defer sync.unlock(&cell.mu)
	assert(slot.state == .Filling && count >= 0 && count <= len(slot.storage))

	if cell.closed || count == 0 {
		slot.state = .Free
		return false
	}

	cell.sequence += 1
	slot.sequence = cell.sequence
	slot.used = count
	slot.state = .Ready

	return true
}

abandon_output :: proc(slot: ^Output) {
	if slot == nil {
		return
	}

	sync.lock(&slot.channel.mu)
	assert(slot.state == .Filling)
	slot.state = .Free
	slot.used = 0
	sync.unlock(&slot.channel.mu)
}

next :: proc(cell: ^Channel, destination: ^owned.Chunk) -> (Read_Status, Error) {
	if destination == nil || aliases(cell, destination, size_of(owned.Chunk)) || !chunk_empty(destination) {
		return .Pending, {kind = .Invalid}
	}

	sync.lock(&cell.mu)

	if cell.error.kind != .None {
		error := cell.error
		sync.unlock(&cell.mu)
		return .Pending, {http = error}
	}

	selected: ^Output

	for &slot in cell.outputs[:cell.bank.limits.response_chunks] {
		if slot.state == .Ready && (selected == nil || slot.sequence < selected.sequence) {
			selected = &slot
		}
	}

	if selected != nil {
		if cell.references == max(int) {
			sync.unlock(&cell.mu)
			return .Pending, {kind = .Capacity}
		}

		selected.state = .Taken
		cell.references += 1
		destination^ = {
			data      = selected.storage[:selected.used],
			storage   = selected.storage,
			release   = output_release,
			user_data = selected,
		}

		sync.unlock(&cell.mu)
		return .Chunk, {}
	}

	terminal, closed := cell.terminal, cell.closed
	sync.unlock(&cell.mu)

	if terminal {
		return .End, {}
	}

	if closed {
		return .Pending, {kind = .Closed}
	}

	return .Pending, {}
}

output_release :: proc(storage: []u8, data: rawptr) {
	slot := cast(^Output)data
	cell := slot.channel
	sync.lock(&cell.mu)
	assert(slot.state == .Taken && raw_data(storage) == raw_data(slot.storage) && len(storage) == len(slot.storage))
	slot.state = .Free
	slot.used = 0
	sync.unlock(&cell.mu)
	notify(cell)
	release(cell)
}

head_empty :: proc(head: ^Head) -> bool {
	return(
		head != nil &&
		head._owner == nil &&
		head.response.status == 0 &&
		raw_data(head.response.header_storage) == nil &&
		raw_data(head.response.headers) == nil &&
		raw_data(head.response.body_storage) == nil &&
		cap(head.response.body_storage) == 0 &&
		raw_data(head.response.body) == nil &&
		head.response.allocator.procedure == nil &&
		head.response.allocator.data == nil &&
		head.response._allocator_scope == {} &&
		head.response.body_storage.allocator.procedure == nil &&
		head.response.body_storage.allocator.data == nil \
	)
}

publish_head :: proc(cell: ^Channel, response: ^surf.Response, length: i64, encoding: Encoding) -> bool {
	sync.lock(&cell.mu)
	defer sync.unlock(&cell.mu)

	if cell.closed || cell.head_ready || cell.head_taken {
		return false
	}

	cell.header_bytes = len(response.header_storage) + len(response.headers) * size_of(http.Header)
	cell.head = response^
	response^ = {}
	cell.wire_length = length
	cell.encoding = encoding
	cell.head_ready = true

	return true
}

take_head :: proc(cell: ^Channel, destination: ^Head) -> Error {
	if destination == nil || aliases(cell, destination, size_of(Head)) || !head_empty(destination) {
		return {kind = .Invalid}
	}

	sync.lock(&cell.mu)
	defer sync.unlock(&cell.mu)

	if cell.head_ready {
		if cell.references == max(int) {
			return {kind = .Capacity}
		}

		cell.references += 1
		destination^ = {
			response            = cell.head,
			wire_content_length = cell.wire_length,
			delivery            = cell.encoding,
			_owner              = cell,
		}

		cell.head = {}
		cell.head_ready = false
		cell.head_taken = true
		return {}
	}

	if cell.head_taken {
		return {kind = .Invalid}
	}

	if cell.error.kind != .None {
		return {http = cell.error}
	}

	if cell.closed {
		return {kind = .Closed}
	}

	return {kind = .Pending}
}

head_destroy :: proc(head: ^Head) {
	if head == nil {
		return
	}

	old := head^
	head^ = {}
	surf.response_destroy(&old.response)

	if old._owner != nil {
		sync.lock(&old._owner.mu)
		old._owner.header_bytes = 0
		sync.unlock(&old._owner.mu)
	}

	release(old._owner)
}

complete :: proc(cell: ^Channel, error: surf.HTTP_Error) {
	sync.lock(&cell.mu)

	if cell.error.kind == .None {
		cell.error = error
	}

	cell.terminal = true

	if error.kind != .None {
		cell.closed = true

		for &slot in cell.outputs {
			if slot.state == .Ready {
				slot.state = .Free
				slot.used = 0
			}
		}
	}

	notification := cell.wake
	cell.wake = {}
	sync.unlock(&cell.mu)
	signal.release(&notification)
	stop_upload(cell)
}

release_request :: proc(cell: ^Channel) {
	if cell == nil {
		return
	}

	sync.lock(&cell.mu)
	assert(!cell.request_released)
	cell.request_released = true
	cell.closed = true

	for &slot in cell.outputs {
		if slot.state == .Ready {
			slot.state = .Free
			slot.used = 0
		}
	}

	response := cell.head
	cell.head = {}
	cell.head_ready = false
	notification := cell.wake
	cell.wake = {}
	sync.unlock(&cell.mu)
	signal.release(&notification)
	surf.response_destroy(&response)
	sync.lock(&cell.mu)

	if !cell.head_taken {
		cell.header_bytes = 0
	}

	sync.unlock(&cell.mu)
	stop_upload(cell)
	release(cell)
}

is_closed :: proc(cell: ^Channel) -> bool {
	sync.lock(&cell.mu)
	defer sync.unlock(&cell.mu)

	return cell.closed
}

bank_stats :: proc(bank: ^Bank) -> Stats {
	if bank == nil {
		return {}
	}

	result: Stats
	sync.lock(&bank.mu)
	defer sync.unlock(&bank.mu)

	for entry in bank.cells {
		if !entry.reserved {
			continue
		}

		result.streams += 1

		if entry.returning {
			result.retiring_streams += 1
		}

		cell := entry.channel

		if cell == nil {
			continue
		}

		sync.lock(&cell.mu)

		if cell.request_released {
			result.retiring_streams += 1
		}

		for slot in cell.outputs {
			if slot.state != .Free {
				result.response_chunks += 1
			}

			if slot.state == .Taken {
				result.held_response_chunks += 1
			}
		}

		result.upload_chunks += cell.upload_queued + cell.upload_active
		result.upload_bytes += cell.upload_bytes
		result.response_backing_bytes += len(cell.output_storage)
		result.header_bytes += cell.header_bytes
		sync.unlock(&cell.mu)
	}

	return result
}

MAX_SLOTS :: 16
MAX_CHUNK_BYTES :: 64 << 10
MAX_STREAMS :: 4096
Limits :: struct {
	streams, response_chunks, upload_chunks:        int,
	max_chunk_bytes, max_retained_bytes_per_stream: int,
}
Content_Decoding :: enum {
	Identity,
	Gzip,
}
Options :: struct {
	upload_length:                        Maybe(i64),
	max_encoded_bytes, max_decoded_bytes: u64,
	decoding:                             Content_Decoding,
}
Encoding :: enum {
	Wire,
	Decoded_Gzip,
}
Read_Status :: enum {
	Pending,
	Chunk,
	End,
}
Upload_Status :: enum {
	Accepted,
	Backpressure,
	Closed,
	Invalid,
	Limit_Exceeded,
	Allocation_Failed,
}
Error_Kind :: enum {
	None,
	Invalid,
	Closed,
	Pending,
	Capacity,
	Allocation_Failed,
}
Error :: struct {
	kind: Error_Kind,
	http: surf.HTTP_Error,
}
Head :: struct {
	response:            surf.Response,
	wire_content_length: i64,
	delivery:            Encoding,
	_owner:              ^Channel,
}
Stats :: struct {
	streams, retiring_streams, response_chunks, held_response_chunks:  int,
	upload_chunks, upload_bytes, response_backing_bytes, header_bytes: int,
}
Slot_State :: enum {
	Free,
	Filling,
	Ready,
	Taken,
}
Output :: struct {
	channel:  ^Channel,
	storage:  []u8,
	used:     int,
	state:    Slot_State,
	sequence: u64,
}
// Client and outstanding cells retain this owner independently of the runtime.
Bank :: struct {
	mu:         sync.Mutex,
	references: int,
	closed:     bool,
	limits:     Limits,
	cells:      []Cell_Entry,
	allocator:  mem.Allocator,
	binding:    charged.Binding,
}
Cell_Entry :: struct {
	channel:             ^Channel,
	reserved, returning: bool,
}
Channel :: struct {
	mu:                                                      sync.Mutex,
	bank:                                                    ^Bank,
	index:                                                   int,
	references:                                              int,
	claimed, returning, closed, request_released, terminal:  bool,
	options:                                                 Options,
	wake:                                                    signal.Signal,
	outputs:                                                 [MAX_SLOTS]Output,
	output_storage:                                          []u8,
	sequence:                                                u64,
	uploads:                                                 [MAX_SLOTS]owned.Chunk,
	upload_head, upload_queued, upload_active, upload_bytes: int,
	upload_received:                                         u64,
	upload_finished, upload_stopped:                         bool,
	upload_error:                                            surf.HTTP_Error,
	lease:                                                   scopes.Lease,
	head:                                                    surf.Response,
	head_ready, head_taken:                                  bool,
	wire_length:                                             i64,
	header_bytes:                                            int,
	encoding:                                                Encoding,
	error:                                                   surf.HTTP_Error,
}

limits_normalize :: proc(input: Limits, requests: int) -> (Limits, bool) {
	result := input
	if result.streams == 0 {
		result.streams = min(requests, 8)
	}
	if result.response_chunks == 0 {
		result.response_chunks = 2
	}
	if result.upload_chunks == 0 {
		result.upload_chunks = 2
	}
	if result.max_chunk_bytes == 0 {
		result.max_chunk_bytes = 16 << 10
	}
	if result.max_retained_bytes_per_stream == 0 {
		result.max_retained_bytes_per_stream = 64 << 10
	}
	if result.streams < 1 ||
	   result.streams > min(requests, MAX_STREAMS) ||
	   result.response_chunks < 1 ||
	   result.response_chunks > MAX_SLOTS ||
	   result.upload_chunks < 1 ||
	   result.upload_chunks > MAX_SLOTS ||
	   result.max_chunk_bytes < 1 ||
	   result.max_chunk_bytes > MAX_CHUNK_BYTES ||
	   result.max_retained_bytes_per_stream < result.response_chunks * result.max_chunk_bytes ||
	   result.max_retained_bytes_per_stream > 64 << 20 {
		return {}, false
	}

	return result, true
}

options_normalize :: proc(input: Options, body_limit: int) -> (Options, bool) {
	result := input
	if result.max_encoded_bytes == 0 {
		result.max_encoded_bytes = u64(body_limit)
	}
	if result.max_decoded_bytes == 0 {
		result.max_decoded_bytes = u64(body_limit)
	}
	if result.max_encoded_bytes > 64 << 20 ||
	   result.max_decoded_bytes > 64 << 20 ||
	   result.max_encoded_bytes == 0 ||
	   result.max_decoded_bytes == 0 {
		return {}, false
	}

	if size, yes := result.upload_length.?; yes && size < 0 {
		return {}, false
	}

	if result.decoding != .Identity && result.decoding != .Gzip {
		return {}, false
	}

	return result, true
}

upload_submit :: proc(cell: ^Channel, source: ^owned.Chunk) -> (Upload_Status, Error) {
	if source == nil || aliases(cell, source, size_of(owned.Chunk)) || !owned.valid(source) || len(source.data) == 0 {
		return .Invalid, {kind = .Invalid}
	}

	limits := cell.bank.limits

	if len(source.storage) > limits.max_chunk_bytes || len(source.data) > limits.max_chunk_bytes {
		return .Limit_Exceeded, {}
	}

	sync.lock(&cell.mu)

	if cell.closed || cell.upload_finished || cell.upload_stopped {
		sync.unlock(&cell.mu)
		return .Closed, {}
	}

	length, upload := cell.options.upload_length.?

	if !upload {
		sync.unlock(&cell.mu)
		return .Invalid, {kind = .Invalid}
	}

	if u64(len(source.data)) > u64(length) - cell.upload_received {
		sync.unlock(&cell.mu)
		return .Limit_Exceeded, {}
	}

	bytes_limit := limits.max_retained_bytes_per_stream - len(cell.output_storage)
	if cell.upload_queued + cell.upload_active == limits.upload_chunks ||
	   len(source.storage) > bytes_limit - cell.upload_bytes {
		sync.unlock(&cell.mu)
		return .Backpressure, {}
	}

	index := (cell.upload_head + cell.upload_queued) % limits.upload_chunks
	assert(owned.move(&cell.uploads[index], source))
	cell.upload_queued += 1
	cell.upload_bytes += len(cell.uploads[index].storage)
	cell.upload_received += u64(len(cell.uploads[index].data))
	sync.unlock(&cell.mu)
	notify(cell)

	return .Accepted, {}
}

upload_finish :: proc(cell: ^Channel, source_error: io.Error = nil) -> Error {
	sync.lock(&cell.mu)
	length, upload := cell.options.upload_length.?

	if !upload {
		sync.unlock(&cell.mu)
		return {kind = .Invalid}
	}

	if cell.closed || cell.upload_finished || cell.upload_stopped {
		sync.unlock(&cell.mu)
		return {kind = .Closed}
	}

	cell.upload_finished = true

	if source_error != nil {
		cell.upload_error = {
			kind      = .IO_Failed,
			source_io = source_error,
			phase     = .Write,
		}
	} else if cell.upload_received != u64(length) {
		cell.upload_error = {
			kind  = .Invalid_Content_Length,
			phase = .Write,
		}
	}

	sync.unlock(&cell.mu)
	notify(cell)

	return {}
}

// The active write remains charged after this move and through its destructor.
upload_take :: proc(cell: ^Channel, destination: ^owned.Chunk) -> (bool, bool, surf.HTTP_Error) {
	sync.lock(&cell.mu)
	defer sync.unlock(&cell.mu)

	if cell.upload_error.kind != .None {
		return false, false, cell.upload_error
	}

	if cell.upload_queued > 0 {
		assert(cell.upload_active == 0)
		assert(owned.move(destination, &cell.uploads[cell.upload_head]))
		cell.upload_head = (cell.upload_head + 1) % cell.bank.limits.upload_chunks
		cell.upload_queued -= 1
		cell.upload_active += 1
		return true, false, {}
	}

	return false, cell.upload_finished || cell.upload_stopped, {}
}

upload_release :: proc(cell: ^Channel, chunk: ^owned.Chunk) {
	bytes := len(chunk.storage)
	owned.destroy(chunk)
	sync.lock(&cell.mu)
	assert(cell.upload_active == 1 && cell.upload_bytes >= bytes)
	cell.upload_active = 0
	cell.upload_bytes -= bytes
	sync.unlock(&cell.mu)
}

// Queued sources are detached before arbitrary producer release callbacks run.
stop_upload :: proc(cell: ^Channel) {
	discarded: [MAX_SLOTS]owned.Chunk
	bytes := 0
	sync.lock(&cell.mu)
	cell.upload_stopped = true

	for &chunk, i in cell.uploads {
		bytes += len(chunk.storage)
		discarded[i] = chunk
		chunk = {}
	}

	cell.upload_queued = 0
	cell.upload_head = 0
	sync.unlock(&cell.mu)

	for &chunk in discarded {
		owned.destroy(&chunk)
	}

	sync.lock(&cell.mu)
	cell.upload_bytes -= bytes
	sync.unlock(&cell.mu)
}

// Producer failure wakes the actor even while an accepted write is blocked.
upload_failure :: proc(cell: ^Channel) -> surf.HTTP_Error {
	sync.lock(&cell.mu)
	defer sync.unlock(&cell.mu)

	return cell.upload_error
}
