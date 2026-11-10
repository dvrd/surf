package surf_stream

import surf "../.."
import signal "../../../async/signal"
import "core:sync"

complete :: proc(cell:^Channel,error:surf.HTTP_Error) {
 sync.lock(&cell.mu)
 if cell.error.kind==.None {cell.error=error}
 cell.terminal=true
 if error.kind!=.None {
  cell.closed=true
  for &slot in cell.outputs {if slot.state==.Ready {slot.state=.Free;slot.used=0}}
 }
 notification:=cell.wake;cell.wake={}
 sync.unlock(&cell.mu)
 signal.release(&notification)
 stop_upload(cell)
}

release_request :: proc(cell:^Channel) {
 if cell==nil {return}
 sync.lock(&cell.mu)
 assert(!cell.request_released)
 cell.request_released=true;cell.closed=true
 for &slot in cell.outputs {if slot.state==.Ready {slot.state=.Free;slot.used=0}}
 response:=cell.head;cell.head={};cell.head_ready=false
 notification:=cell.wake;cell.wake={}
 sync.unlock(&cell.mu)
 signal.release(&notification)
 surf.response_destroy(&response)
 sync.lock(&cell.mu);if !cell.head_taken {cell.header_bytes=0};sync.unlock(&cell.mu)
 stop_upload(cell)
 release(cell)
}

is_closed :: proc(cell:^Channel)->bool {
 sync.lock(&cell.mu);defer sync.unlock(&cell.mu)
 return cell.closed
}

bank_stats :: proc(bank:^Bank)->Stats {
 if bank==nil {return {}}
 result:Stats
 sync.lock(&bank.mu);defer sync.unlock(&bank.mu)
 for entry in bank.cells {
  if !entry.reserved {continue}
  result.streams+=1
  if entry.returning {result.retiring_streams+=1}
  cell:=entry.channel
  if cell==nil {continue}
  sync.lock(&cell.mu)
  if cell.request_released {result.retiring_streams+=1}
  for slot in cell.outputs {
   if slot.state!=.Free {result.response_chunks+=1}
   if slot.state==.Taken {result.held_response_chunks+=1}
  }
  result.upload_chunks+=cell.upload_queued+cell.upload_active
  result.upload_bytes+=cell.upload_bytes
  result.response_backing_bytes+=len(cell.output_storage)
  result.header_bytes+=cell.header_bytes
  sync.unlock(&cell.mu)
 }
 return result
}
