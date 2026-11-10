package surf_exchange

// Owner-loop metadata only. Query after an API call returns, never concurrently
// with a drive or from its allocator/provider callbacks. Reading_Head begins
// only after the final accepted request-write callback has been consumed.
// No transport/TLS readiness, peer liveness or closed-quiescence is implied.
// Reentrant/busy and copied/uninitialized owners reject without mutation.
exchange_phase :: proc(x:^Exchange)->(Exchange_Phase,bool) {
 if !exchange_valid(x) || x._busy {return {},false}
 switch x._phase {
 case .Idle,.Writing_Head,.Writing_Body,.Reading_Head,.Copying_Head,.Reading_Body,.Draining,.Done:
  return x._phase,true
 case:
  return {},false
 }
}
