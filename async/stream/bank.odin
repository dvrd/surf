package surf_stream

import surf "../.."
import signal "../../../async/signal"
import "core:mem"
import charged "core:mem/budget"
import "core:mem/owned"
import "core:sync"
import scopes "core:sync/budget"

@(private)
allocation_error :: proc(cause: mem.Allocator_Error) -> Error {
 return {kind=.Allocation_Failed,http={kind=.Allocation_Failed,allocation=cause}}
}

bank_create :: proc(input: Limits, allocator: mem.Allocator) -> (^Bank, Error) {
 limits,valid:=limits_normalize(input,MAX_STREAMS)
 if !valid || allocator.procedure == nil {return nil,{kind=.Invalid}}
 binding: charged.Binding
 if charged.is_managed_allocator(allocator) {
  retained,error := charged.retain_allocator(allocator)
  if error.kind != .None {return nil,allocation_error(error.allocation)}
  binding=retained
 }
 bank,cause := create_value(Bank,allocator)
 if cause != nil {charged.release(&binding);return nil,allocation_error(cause)}
 bank^={references=1,limits=limits,allocator=allocator,binding=binding}
 cells,error := create_array(Cell_Entry,limits.streams,allocator)
 if error != nil {free(bank,allocator);charged.release(&binding);return nil,allocation_error(error)}
 bank.cells=cells
 return bank,{}
}

@(private)
bank_drop :: proc(bank: ^Bank) {
 sync.lock(&bank.mu)
 assert(bank.references>0)
 bank.references-=1
 last:=bank.references==0
 sync.unlock(&bank.mu)
 if !last {return}
 cells,allocator,binding:=bank.cells,bank.allocator,bank.binding
 delete(cells,allocator)
 free(bank,allocator)
 charged.release(&binding)
}

bank_close :: proc(owner: ^^Bank) {
 if owner==nil || owner^==nil {return}
 bank:=owner^;owner^=nil
 sync.lock(&bank.mu);bank.closed=true;sync.unlock(&bank.mu)
 bank_drop(bank)
}

channel_create :: proc(bank: ^Bank, input: Options) -> (^Channel,Error) {
 if bank==nil {return nil,{kind=.Invalid}}
 options,valid:=options_normalize(input,8<<20)
 if !valid {return nil,{kind=.Invalid}}
 sync.lock(&bank.mu)
 index:=-1
 if !bank.closed {
  for &entry,i in bank.cells {if !entry.reserved {entry.reserved=true;index=i;bank.references+=1;break}}
 }
 closed:=bank.closed
 sync.unlock(&bank.mu)
 if index<0 {return nil,{kind=.Closed if closed else .Capacity}}
 allocator:=bank.allocator
 cell,cause:=create_value(Channel,allocator)
 if cause!=nil {bank_unclaim(bank,index);return nil,allocation_error(cause)}
 cell^={bank=bank,index=index,references=1,claimed=true,options=options,wire_length=-1}
 storage,error:=create_array(u8,bank.limits.response_chunks*bank.limits.max_chunk_bytes,allocator)
 if error!=nil {free(cell,allocator);bank_unclaim(bank,index);return nil,allocation_error(error)}
 cell.output_storage=storage
 for i in 0..<bank.limits.response_chunks {
  start:=i*bank.limits.max_chunk_bytes
  cell.outputs[i]={channel=cell,storage=storage[start:start+bank.limits.max_chunk_bytes]}
 }
 sync.lock(&bank.mu)
 bank.cells[index].channel=cell
 closed=bank.closed
 sync.unlock(&bank.mu)
 if closed {release(cell);return nil,{kind=.Closed}}
 return cell,{}
}

@(private)
bank_unclaim :: proc(bank:^Bank,index:int) {
 sync.lock(&bank.mu)
 bank.cells[index]={}
 sync.unlock(&bank.mu)
 bank_drop(bank)
}

retain :: proc(cell:^Channel)->bool {
 if cell==nil {return false}
 sync.lock(&cell.mu);defer sync.unlock(&cell.mu)
 if cell.references<1 || cell.references==max(int) {return false}
 cell.references+=1
 return true
}

// No allocator, application destructor or Signal wake runs under these locks.
release :: proc(cell:^Channel) {
 if cell==nil {return}
 sync.lock(&cell.mu)
 assert(cell.references>0)
 cell.references-=1
 last:=cell.references==0
 if last {cell.returning=true}
 sync.unlock(&cell.mu)
 if !last {return}
 bank,index,lease:=cell.bank,cell.index,cell.lease
 sync.lock(&bank.mu);bank.cells[index].channel=nil;bank.cells[index].returning=true;sync.unlock(&bank.mu)
 notification:=cell.wake
 signal.release(&notification)
 for &chunk in cell.uploads {owned.destroy(&chunk)}
 surf.response_destroy(&cell.head)
 delete(cell.output_storage,bank.allocator)
 free(cell,bank.allocator)
 bank_unclaim(bank,index)
 scopes.release(&lease)
}

adopt_lease :: proc(cell:^Channel,source:^scopes.Lease) {
 sync.lock(&cell.mu);cell.lease=source^;source^={};sync.unlock(&cell.mu)
}

set_notify :: proc(cell:^Channel,source:signal.Signal) {
 next,_:=signal.retain(source)
 sync.lock(&cell.mu);previous:=cell.wake;cell.wake=next;sync.unlock(&cell.mu)
 signal.release(&previous)
}

@(private)
notify :: proc(cell:^Channel) {
 sync.lock(&cell.mu);wake,_:=signal.retain(cell.wake);sync.unlock(&cell.mu)
 _=signal.wake(wake)
 signal.release(&wake)
}

@(private)
create_array :: proc($T:typeid,count:int,allocator:mem.Allocator)->([]T,mem.Allocator_Error) {
 if count<0 || count>max(int)/size_of(T) {return nil,.Out_Of_Memory}
 size:=count*size_of(T)
 storage,cause:=allocator.procedure(allocator.data,.Alloc,size,align_of(T),nil,0)
 if cause!=nil || len(storage)!=size || (size>0 && raw_data(storage)==nil) ||
    uintptr(raw_data(storage))%uintptr(align_of(T))!=0 {
  if raw_data(storage)!=nil {_,_=allocator.procedure(allocator.data,.Free,0,align_of(T),raw_data(storage),len(storage))}
  return nil,.Out_Of_Memory if cause==nil else cause
 }
 for &value in storage {value=0}
 return (cast([^]T)raw_data(storage))[:count],nil
}

@(private)
create_value :: proc($T:typeid,allocator:mem.Allocator)->(^T,mem.Allocator_Error) {
 storage,error:=create_array(T,1,allocator)
 if error!=nil {return nil,error}
 return &storage[0],nil
}
