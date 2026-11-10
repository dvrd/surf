package surf_stream

import "core:mem/owned"
import "core:sync"

reserve_output :: proc(cell:^Channel)->(^Output,[]u8) {
 sync.lock(&cell.mu);defer sync.unlock(&cell.mu)
 if cell.closed {return nil,nil}
 for &slot in cell.outputs[:cell.bank.limits.response_chunks] {
  if slot.state==.Free {slot.state=.Filling;return &slot,slot.storage}
 }
 return nil,nil
}

publish_output :: proc(slot:^Output,count:int)->bool {
 cell:=slot.channel
 sync.lock(&cell.mu);defer sync.unlock(&cell.mu)
 assert(slot.state==.Filling && count>=0 && count<=len(slot.storage))
 if cell.closed || count==0 {slot.state=.Free;return false}
 cell.sequence+=1;slot.sequence=cell.sequence;slot.used=count;slot.state=.Ready
 return true
}

abandon_output :: proc(slot:^Output) {
 if slot==nil {return}
 sync.lock(&slot.channel.mu)
 assert(slot.state==.Filling)
 slot.state=.Free;slot.used=0
 sync.unlock(&slot.channel.mu)
}

next :: proc(cell:^Channel,destination:^owned.Chunk)->(Read_Status,Error) {
 if destination==nil || aliases(cell,destination,size_of(owned.Chunk)) || !chunk_empty(destination) {return .Pending,{kind=.Invalid}}
 sync.lock(&cell.mu)
 if cell.error.kind!=.None {error:=cell.error;sync.unlock(&cell.mu);return .Pending,{http=error}}
 selected:^Output
 for &slot in cell.outputs[:cell.bank.limits.response_chunks] {
  if slot.state==.Ready && (selected==nil || slot.sequence<selected.sequence) {selected=&slot}
 }
 if selected!=nil {
  if cell.references==max(int) {sync.unlock(&cell.mu);return .Pending,{kind=.Capacity}}
  selected.state=.Taken;cell.references+=1
  destination^={data=selected.storage[:selected.used],storage=selected.storage,
    release=output_release,user_data=selected}
  sync.unlock(&cell.mu)
  return .Chunk,{}
 }
 terminal,closed:=cell.terminal,cell.closed
 sync.unlock(&cell.mu)
 if terminal {return .End,{}}
 if closed {return .Pending,{kind=.Closed}}
 return .Pending,{}
}

@(private)
output_release :: proc(storage:[]u8,data:rawptr) {
 slot:=cast(^Output)data;cell:=slot.channel
 sync.lock(&cell.mu)
 assert(slot.state==.Taken && raw_data(storage)==raw_data(slot.storage) && len(storage)==len(slot.storage))
 slot.state=.Free;slot.used=0
 sync.unlock(&cell.mu)
 notify(cell)
 release(cell)
}
