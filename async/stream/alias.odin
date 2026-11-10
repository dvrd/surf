package surf_stream

import http "../../../http"
import "core:mem/owned"
import "core:sync"

@(private)
range_overlap :: proc(a:rawptr,an:int,b:rawptr,bn:int)->bool {
 if an<=0 || bn<=0 {return false}
 av,bv:=uintptr(a),uintptr(b)
 return av<=bv && bv-av<uintptr(an) || bv<av && av-bv<uintptr(bn)
}

aliases :: proc(cell:^Channel,destination:rawptr,size:int)->bool {
 bank:=cell.bank
 if range_overlap(destination,size,cell,size_of(Channel)) ||
    range_overlap(destination,size,bank,size_of(Bank)) ||
    range_overlap(destination,size,raw_data(bank.cells),len(bank.cells)*size_of(Cell_Entry)) ||
    range_overlap(destination,size,raw_data(cell.output_storage),len(cell.output_storage)) {return true}
 sync.lock(&cell.mu);defer sync.unlock(&cell.mu)
 if range_overlap(destination,size,raw_data(cell.head.header_storage),len(cell.head.header_storage)) ||
    range_overlap(destination,size,raw_data(cell.head.headers),len(cell.head.headers)*size_of(http.Header)) {return true}
 for chunk in cell.uploads {
  if range_overlap(destination,size,raw_data(chunk.storage),len(chunk.storage)) {return true}
 }
 return false
}

chunk_empty :: proc(chunk:^owned.Chunk)->bool {
 return chunk!=nil && chunk.release==nil && chunk.allocator.procedure==nil &&
  raw_data(chunk.data)==nil && raw_data(chunk.storage)==nil &&
  chunk.user_data==nil && chunk.allocator.data==nil
}
