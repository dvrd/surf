package surf_exchange

import channel "../stream"
import gzip "core:compress/gzip"
import "core:mem/owned"

Stream_TX :: enum {Head, Body, Upload, Done, Stopped}
// Separate TX/RX state preserves the existing buffered Exchange unchanged.
Stream_Exchange :: struct {
 base: Exchange,
 channel: ^channel.Channel,
 tx: Stream_TX,
 decoder: gzip.Decoder,
 upload: owned.Chunk,
 upload_at, write_requested: int,
 encoded: [READ_BUFFER_SIZE]u8,
 discard: [READ_BUFFER_SIZE]u8,
 encoded_at, encoded_used: int,
 encoded_total, delivered_total: u64,
 decoded, entity_done, rx_done, early_response, head_pending: bool,
 private_response, redirects, upload_released: bool,
 status: int,
}
