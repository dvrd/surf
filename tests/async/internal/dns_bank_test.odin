package surf_async
import "core:bytes"
import "core:fmt"
import "core:mem"
import "core:net"
import runtime_async "../../async"
import "core:testing"
bank_refill :: proc(s:^Client_State,ids:[]u16)->Client_Error {
 previous:=context;context.allocator,context.temp_allocator=mem.panic_allocator(),mem.panic_allocator()
 defer context=previous;return network_dns_refill(s,ids)
}
bank_reserve :: proc(s:^Client_State,maximum:int)->(DNS_ID_Block,Client_Error) {
 previous:=context;context.allocator,context.temp_allocator=mem.panic_allocator(),mem.panic_allocator()
 defer context=previous;return network_dns_reserve(s,maximum)
}
bank_burn :: proc(s:^Client_State,block:^DNS_ID_Block) {
 previous:=context;context.allocator,context.temp_allocator=mem.panic_allocator(),mem.panic_allocator()
 defer context=previous;network_dns_burn(s,block)
}
bank_prepare :: proc(r:^runtime_async.Runtime,capacity:int,allocator:mem.Allocator)->^Client_State {
 config:=bootstrap_config({},capacity);servers:=[1]net.Endpoint{{net.IP4_Loopback,53}}
 // Positive capacity uses actual explicit snapshot+OS entropy, no system files
 // or DNS query/socket traffic. The endpoints are cloned before return.
 if capacity>0 {config.http.resolver.name_servers=servers[:]}
 state,error:=network_prepare(r,config,allocator);assert(error.kind==.None);return state
}
bank_empty :: proc(s:^Client_State) {
 for s.dns_count>0 {block,error:=bank_reserve(s,16);assert(error.kind==.None);bank_burn(s,&block)}
}
@(test)
dns_bank_actual_prepared_draws_refill_wrap_and_move_once :: proc(t:^testing.T) {
 r:runtime_async.Runtime;bootstrap_runtime(&r)
 f:=Ownership_Fault{backing=context.allocator};s:=bank_prepare(&r,17,{ownership_allocate,&f})
 testing.expect_value(t,s.config.dns_preparation,.Explicit)
 servers,valid:=net.resolver_snapshot_name_servers(&s.resolver)
 testing.expect(t,valid && len(servers)==1 && servers[0].port==53)
 testing.expect_value(t,s.dns_count,17);bank_empty(s)
 source:[17]u16;for &v,i in source {v=u16(100+i)}
 original:=source;calls:=f.calls
 assert(bank_refill(s,source[:]).kind==.None)
 testing.expect_value(t,source,original)
 for &v in source {v=999}
 first,error:=bank_reserve(s,12);assert(error.kind==.None && first.count==12)
 for v,i in first.values[:first.count] {testing.expect_value(t,v,u16(100+i))}
 bank_burn(s,&first);testing.expect_value(t,first,DNS_ID_Block{})
 burned:=s.dns_draws_burned;bank_burn(s,&first);testing.expect_value(t,s.dns_draws_burned,burned)
 next:=[12]u16{200,201,202,203,204,205,206,207,208,209,210,211}
 assert(bank_refill(s,next[:]).kind==.None)
 wrapped,we:=bank_reserve(s,16);assert(we.kind==.None && wrapped.count==16)
 for i in 0..<16 {want:=u16(112+i) if i<5 else u16(200+i-5);testing.expect_value(t,wrapped.values[i],want)}
 bank_burn(s,&wrapped)
 last,le:=bank_reserve(s,16);assert(le.kind==.None && last.count==1)
 testing.expect_value(t,last.values[0],u16(211));bank_burn(s,&last)
 empty,ee:=bank_reserve(s,1);testing.expect(t,ee.kind==.Pending && empty==(DNS_ID_Block{}))
 testing.expect_value(t,f.calls,calls)
 testing.expect_value(t,s.dns_draws_reserved,u64(46));testing.expect_value(t,s.dns_draws_burned,u64(46))
 assert(network_dispose_prepared(s).kind==.None && runtime_async.destroy(&r).kind==.None)
 fmt.println("DNS_BANK16 prepared_ids=17 known_refill_ids=29 ordered_wrap=true draws_reserved_burned=46 noalloc=true")
}
@(test)
dns_bank_invalid_capacity_shapes_and_internal_aliases_preserve_sources :: proc(t:^testing.T) {
 r:runtime_async.Runtime;bootstrap_runtime(&r)
 f:=Ownership_Fault{backing=context.allocator};s:=bank_prepare(&r,17,{ownership_allocate,&f})
 before:[17]u16;copy(before[:],s.dns_ids)
 head,count,reserved,burned:=s.dns_head,s.dns_count,s.dns_draws_reserved,s.dns_draws_burned
 for maximum in ([5]int{0,-1,17,min(int),max(int)}) {block,error:=bank_reserve(s,maximum);testing.expect(t,error.kind==.Invalid_Config && block==(DNS_ID_Block{}))}
 source:=[2]u16{10,11};original:=source
 testing.expect_value(t,bank_refill(s,source[:]).kind,.Capacity);testing.expect_value(t,source,original)
 aliases:=[5]rawptr{s,raw_data(s.actors),raw_data(s.requests),raw_data(s.task_index),raw_data(s.dns_ids)}
 calls:=f.calls
 for pointer in aliases {input:=(cast([^]u16)pointer)[:1];testing.expect_value(t,bank_refill(s,input).kind,.Invalid_Config)}
 for length in ([3]int{-1,1,65537}) {
  malformed:[]u16;(cast(^mem.Raw_Slice)&malformed)^={data=nil,len=length}
  testing.expect_value(t,bank_refill(s,malformed).kind,.Invalid_Config)
 }
 testing.expect_value(t,s.dns_head,head);testing.expect_value(t,s.dns_count,count)
 testing.expect_value(t,s.dns_draws_reserved,reserved);testing.expect_value(t,s.dns_draws_burned,burned)
 testing.expect(t,bytes.equal(mem.slice_to_bytes(before[:]),mem.slice_to_bytes(s.dns_ids)))
 testing.expect_value(t,f.calls,calls);assert(bank_refill(s,nil).kind==.None)
 assert(network_dispose_prepared(s).kind==.None && runtime_async.destroy(&r).kind==.None)
 fmt.println("DNS_BANK16 atomic_rejection_cells=14 internal_aliases=5 sources_preserved=true")
}
@(test)
dns_bank_zero_capacity_and_saturating_scalar_accounting_are_literal :: proc(t:^testing.T) {
 r:runtime_async.Runtime;bootstrap_runtime(&r)
 zero:=bank_prepare(&r,0,context.allocator)
 testing.expect_value(t,len(zero.dns_ids),0);assert(bank_refill(zero,nil).kind==.None)
 block,error:=bank_reserve(zero,1);testing.expect(t,error.kind==.Pending && block==(DNS_ID_Block{}))
 source:=[1]u16{7};testing.expect_value(t,bank_refill(zero,source[:]).kind,.Capacity)
 testing.expect_value(t,source[0],u16(7));assert(network_dispose_prepared(zero).kind==.None)
 s:=bank_prepare(&r,1,context.allocator)
 // Local counter boundary injection, not billions of actual queries.
 s.dns_draws_reserved=max(u64)-1;s.dns_draws_burned=max(u64)-1
 owned,cause:=bank_reserve(s,1);assert(cause.kind==.None)
 testing.expect_value(t,s.dns_draws_reserved,max(u64));bank_burn(s,&owned)
 testing.expect_value(t,s.dns_draws_burned,max(u64))
 assert(bank_refill(s,source[:]).kind==.None)
 owned,cause=bank_reserve(s,1);assert(cause.kind==.None);bank_burn(s,&owned)
 testing.expect_value(t,s.dns_draws_reserved,max(u64));testing.expect_value(t,s.dns_draws_burned,max(u64))
 for invalid in ([3]int{-1,17,max(int)}) {bad:=DNS_ID_Block{count=invalid};bank_burn(s,&bad);testing.expect_value(t,bad,DNS_ID_Block{});testing.expect_value(t,s.dns_draws_burned,max(u64))}
 assert(network_dispose_prepared(s).kind==.None && runtime_async.destroy(&r).kind==.None)
}
