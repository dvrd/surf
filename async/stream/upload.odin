package surf_stream

import surf "../.."
import "core:io"
import "core:mem/owned"
import "core:sync"

upload_submit :: proc(cell:^Channel,source:^owned.Chunk)->(Upload_Status,Error) {
 if source==nil || aliases(cell,source,size_of(owned.Chunk)) || !owned.valid(source) || len(source.data)==0 {return .Invalid,{kind=.Invalid}}
 limits:=cell.bank.limits
 if len(source.storage)>limits.max_chunk_bytes || len(source.data)>limits.max_chunk_bytes {
  return .Limit_Exceeded,{}
 }
 sync.lock(&cell.mu)
 if cell.closed || cell.upload_finished || cell.upload_stopped {
  sync.unlock(&cell.mu);return .Closed,{}
 }
 length,upload:=cell.options.upload_length.?
 if !upload {sync.unlock(&cell.mu);return .Invalid,{kind=.Invalid}}
 if u64(len(source.data))>u64(length)-cell.upload_received {
  sync.unlock(&cell.mu);return .Limit_Exceeded,{}
 }
 bytes_limit:=limits.max_retained_bytes_per_stream-len(cell.output_storage)
 if cell.upload_queued+cell.upload_active==limits.upload_chunks ||
    len(source.storage)>bytes_limit-cell.upload_bytes {
  sync.unlock(&cell.mu);return .Backpressure,{}
 }
 index:=(cell.upload_head+cell.upload_queued)%limits.upload_chunks
 assert(owned.move(&cell.uploads[index],source))
 cell.upload_queued+=1
 cell.upload_bytes+=len(cell.uploads[index].storage)
 cell.upload_received+=u64(len(cell.uploads[index].data))
 sync.unlock(&cell.mu)
 notify(cell)
 return .Accepted,{}
}

upload_finish :: proc(cell:^Channel,source_error:io.Error=nil)->Error {
 sync.lock(&cell.mu)
 length,upload:=cell.options.upload_length.?
 if !upload {sync.unlock(&cell.mu);return {kind=.Invalid}}
 if cell.closed || cell.upload_finished || cell.upload_stopped {sync.unlock(&cell.mu);return {kind=.Closed}}
 cell.upload_finished=true
 if source_error!=nil {cell.upload_error={kind=.IO_Failed,source_io=source_error,phase=.Write}}
 else if cell.upload_received!=u64(length) {cell.upload_error={kind=.Invalid_Content_Length,phase=.Write}}
 sync.unlock(&cell.mu)
 notify(cell)
 return {}
}

// The active write remains charged after this move and through its destructor.
upload_take :: proc(cell:^Channel,destination:^owned.Chunk)->(bool,bool,surf.HTTP_Error) {
 sync.lock(&cell.mu);defer sync.unlock(&cell.mu)
 if cell.upload_error.kind!=.None {return false,false,cell.upload_error}
 if cell.upload_queued>0 {
  assert(cell.upload_active==0)
  assert(owned.move(destination,&cell.uploads[cell.upload_head]))
  cell.upload_head=(cell.upload_head+1)%cell.bank.limits.upload_chunks
  cell.upload_queued-=1;cell.upload_active+=1
  return true,false,{}
 }
 return false,cell.upload_finished || cell.upload_stopped,{}
}

upload_release :: proc(cell:^Channel,chunk:^owned.Chunk) {
 bytes:=len(chunk.storage)
 owned.destroy(chunk)
 sync.lock(&cell.mu)
 assert(cell.upload_active==1 && cell.upload_bytes>=bytes)
 cell.upload_active=0;cell.upload_bytes-=bytes
 sync.unlock(&cell.mu)
}

// Queued sources are detached before arbitrary producer release callbacks run.
stop_upload :: proc(cell:^Channel) {
 discarded:[MAX_SLOTS]owned.Chunk
 bytes:=0
 sync.lock(&cell.mu)
 cell.upload_stopped=true
 for &chunk,i in cell.uploads {
  bytes+=len(chunk.storage)
  discarded[i]=chunk;chunk={}
 }
 cell.upload_queued=0;cell.upload_head=0
 sync.unlock(&cell.mu)
 for &chunk in discarded {owned.destroy(&chunk)}
 sync.lock(&cell.mu);cell.upload_bytes-=bytes;sync.unlock(&cell.mu)
}

// Producer failure wakes the actor even while an accepted write is blocked.
upload_failure :: proc(cell:^Channel)->surf.HTTP_Error {
 sync.lock(&cell.mu);defer sync.unlock(&cell.mu)
 return cell.upload_error
}
