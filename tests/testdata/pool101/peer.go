// Independent loopback peer: Go's TLS handshake and RFC8446 record oracle.
package main

import (
 "bufio"
 "crypto/aes"
 "crypto/cipher"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/hmac"
 "crypto/rand"
 "crypto/sha256"
 "crypto/tls"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/binary"
 "encoding/json"
 "encoding/hex"
 "strings"
 "encoding/pem"
 "flag"
 "fmt"
 "io"
 "math/big"
 "net"
 "net/http"
 "os"
 "path/filepath"
 "time"
 "sync"
)

type records struct {net.Conn; secret,clientSecret,clientPending []byte; seq,clientSeq uint64; encrypted,clientUpdates,updates int; manualSequences []uint64}
func expand(secret []byte,label string,n int) []byte {
 label="tls13 "+label
 info:=[]byte{byte(n>>8),byte(n),byte(len(label))};info=append(info,[]byte(label)...);info=append(info,0)
 var out,previous []byte
 for i:=byte(1);len(out)<n;i++ {m:=hmac.New(sha256.New,secret);m.Write(previous);m.Write(info);m.Write([]byte{i});previous=m.Sum(nil);out=append(out,previous...)}
 return out[:n]
}
func (c *records) aead() cipher.AEAD {b,e:=aes.NewCipher(expand(c.secret,"key",16));must(e);a,e:=cipher.NewGCM(b);must(e);return a}
func(c *records) nonce() []byte {iv:=expand(c.secret,"iv",12);var seq [8]byte;binary.BigEndian.PutUint64(seq[:],c.seq);for i:=0;i<8;i++ {iv[4+i]^=seq[i]};return iv}
func(c *records) Write(p []byte)(int,error) {
 // Go's Write calls contain complete records. Only successfully authenticated
 // application-secret records advance this independent sequence oracle.
 if len(c.secret)==0 {return c.Conn.Write(p)}
 for at:=0;at+5<=len(p); {n:=5+int(binary.BigEndian.Uint16(p[at+3:at+5]));if at+n>len(p){panic("partial Go record")};if len(c.secret)>0&&p[at]==23 {if _,e:=c.aead().Open(nil,c.nonce(),p[at+5:at+n],p[at:at+5]);e==nil {c.seq++;c.encrypted++}};at+=n}
 return c.Conn.Write(p)
}
func(c *records) Read(dst []byte)(int,error){
 n,err:=c.Conn.Read(dst)
 if len(c.clientSecret)>0 {
  c.clientPending=append(c.clientPending,dst[:n]...);if len(c.clientPending)>1<<20{panic("fixture inbound cap")}
  for len(c.clientPending)>=5 {length:=5+int(binary.BigEndian.Uint16(c.clientPending[3:5]));if len(c.clientPending)<length{break};wire:=c.clientPending[:length]
   if wire[0]==23 {b,e:=aes.NewCipher(expand(c.clientSecret,"key",16));must(e);a,e:=cipher.NewGCM(b);must(e);iv:=expand(c.clientSecret,"iv",12);var seq [8]byte;binary.BigEndian.PutUint64(seq[:],c.clientSeq);for i:=0;i<8;i++ {iv[4+i]^=seq[i]}
    if plain,e:=a.Open(nil,iv,wire[5:],wire[:5]);e==nil {c.clientSeq++;plain=bytesTrimZero(plain);if len(plain)>=6&&plain[len(plain)-1]==22&&plain[0]==24 {c.clientUpdates++;c.clientSecret=expand(c.clientSecret,"traffic upd",32);c.clientSeq=0}}
   };c.clientPending=c.clientPending[length:]
  }
 };return n,err
}
func bytesTrimZero(p []byte)[]byte{for len(p)>0&&p[len(p)-1]==0 {p=p[:len(p)-1]};return p}
func(c *records) record(body []byte,kind byte) []byte {c.manualSequences=append(c.manualSequences,c.seq);plain:=append(append([]byte{},body...),kind);header:=[]byte{23,3,3,0,0};binary.BigEndian.PutUint16(header[3:],uint16(len(plain)+16));wire:=append(header,c.aead().Seal(nil,c.nonce(),plain,header)...);c.seq++;return wire}
func(c *records) keyUpdate() {c.updates++;wire:=c.record([]byte{24,0,0,1,1},22);_,e:=c.Conn.Write(wire);must(e);c.secret=expand(c.secret,"traffic upd",32);c.seq=0}
func must(e error){if e!=nil {panic(e)}}
type poolEvent struct {Connection int `json:"connection"`;Order int `json:"order"`;Path string `json:"path"`;Method string `json:"method"`;Host string `json:"host"`;Body string `json:"body"`;ALPN string `json:"alpn"`;SNI string `json:"sni"`;Secure bool `json:"secure"`}
func main(){
 mode:=flag.String("mode","framing","owned schedule");encrypted:=flag.Bool("tls",false,"TLS13");dir:=flag.String("dir","","fixture directory");flag.Parse();must(os.MkdirAll(*dir,0700))
 listener,e:=net.Listen("tcp4","127.0.0.1:0");must(e);defer listener.Close()
 second,e:=net.Listen("tcp4","127.0.0.1:0");must(e);defer second.Close();must(os.WriteFile(filepath.Join(*dir,"second.endpoint"),[]byte(second.Addr().String()),0600))
 dns,e:=net.ListenPacket("udp4","127.0.0.1:0");must(e);defer dns.Close();must(os.WriteFile(filepath.Join(*dir,"dns.endpoint"),[]byte(dns.LocalAddr().String()),0600))
 go dnsServe(dns)
 var config *tls.Config
 if *encrypted {
  key,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);must(e)
  template:=&x509.Certificate{SerialNumber:big.NewInt(129),Subject:pkix.Name{CommonName:"pool.test"},DNSNames:[]string{"localhost","a.pool.test","b.pool.test"},IPAddresses:[]net.IP{net.ParseIP("127.0.0.1")},NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour),KeyUsage:x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,BasicConstraintsValid:true,IsCA:true,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
  der,e:=x509.CreateCertificate(rand.Reader,template,template,&key.PublicKey,key);must(e)
  must(os.WriteFile(filepath.Join(*dir,"root.pem"),pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),0600))
  wrong,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);must(e);template.SerialNumber=big.NewInt(130);bad,e:=x509.CreateCertificate(rand.Reader,template,template,&wrong.PublicKey,wrong);must(e);must(os.WriteFile(filepath.Join(*dir,"wrong.pem"),pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:bad}),0600))
  config=&tls.Config{Certificates:[]tls.Certificate{{Certificate:[][]byte{der},PrivateKey:key}},MinVersion:tls.VersionTLS13,MaxVersion:tls.VersionTLS13,SessionTicketsDisabled:true,NextProtos:[]string{"http/1.1"}}
 }
 var mu sync.Mutex;events:=[]poolEvent{};connections:=0;var wg sync.WaitGroup;keyUpdates,clientUpdates:=0,0;handshakeErrors:=0
 handle:=func(conn net.Conn,id int){defer wg.Done();defer conn.Close();must(conn.SetDeadline(time.Now().Add(12*time.Second)));var stream net.Conn=conn;alpn,sni:="","";secureConnection:=*encrypted
  if *mode=="scheme" {peek:=bufio.NewReader(conn);first,e:=peek.Peek(1);if e!=nil{return};secureConnection=first[0]==22;stream=&readerConn{Conn:conn,reader:peek}}
  raw:=&records{Conn:stream};stream=raw;manual:=false
  defer func(){mu.Lock();keyUpdates+=raw.updates;clientUpdates+=raw.clientUpdates;mu.Unlock()}()
  if secureConnection {cfg:=config.Clone();cfg.KeyLogWriter=writerFunc(func(p []byte)(int,error){parts:=strings.Fields(string(p));if len(parts)==3 {var err error;if parts[0]=="SERVER_TRAFFIC_SECRET_0"{raw.secret,err=hex.DecodeString(parts[2]);must(err)};if parts[0]=="CLIENT_TRAFFIC_SECRET_0"{raw.clientSecret,err=hex.DecodeString(parts[2]);must(err)}};return len(p),nil});secure:=tls.Server(raw,cfg);if e:=secure.Handshake();e!=nil{mu.Lock();handshakeErrors++;mu.Unlock();return};stream=secure;alpn=secure.ConnectionState().NegotiatedProtocol;sni=secure.ConnectionState().ServerName;if alpn!="http/1.1"{panic("unexpected negotiated protocol")}}
  defer stream.Close() // TLS EOF vectors require authenticated close_notify.
  reader:=bufio.NewReader(stream)
  for order:=1;order<=64;order++ {
   request,e:=http.ReadRequest(reader);if e!=nil{return};body,e:=io.ReadAll(io.LimitReader(request.Body,1<<20));must(e);must(request.Body.Close())
   mu.Lock();events=append(events,poolEvent{id,order,request.URL.Path,request.Method,request.Host,string(body),alpn,sni,secureConnection});mu.Unlock()
   head:=fmt.Sprintf("X-Connection: %d\r\nX-Order: %d\r\n",id,order)
   wire:="";closeAfter:=false
   switch request.URL.Path {
   case "/zero":wire="HTTP/1.1 200 OK\r\n"+head+"Content-Length: 0\r\n\r\n"
   case "/head":if request.Method!="HEAD"{panic("HEAD vector")};wire="HTTP/1.1 200 OK\r\n"+head+"Content-Length: 999\r\n\r\n"
   case "/204":wire="HTTP/1.1 204 No Content\r\n"+head+"\r\n"
   case "/304":wire="HTTP/1.1 304 Not Modified\r\n"+head+"Content-Length: 999\r\n\r\n"
   case "/chunked":wire="HTTP/1.1 200 OK\r\n"+head+"Transfer-Encoding: chunked\r\n\r\n1\r\na\r\n2\r\nbc\r\n0\r\nX-End: yes\r\n\r\n"
   case "/interim":wire="HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"+head+"Content-Length: 2\r\n\r\nok"
   case "/http10":wire="HTTP/1.0 200 OK\r\n"+head+"Connection: keep-alive\r\nContent-Length: 2\r\n\r\nok"
   case "/close":wire="HTTP/1.1 200 OK\r\n"+head+"Connection: close\r\nContent-Length: 2\r\n\r\nok";closeAfter=true
   case "/http10-close":wire="HTTP/1.0 200 OK\r\n"+head+"Content-Length: 2\r\n\r\nok"
   case "/connection-close":wire="HTTP/1.1 200 OK\r\n"+head+"cOnNeCtIoN: keep-alive, , close\r\nContent-Length: 2\r\n\r\nok"
   case "/eof":wire="HTTP/1.1 200 OK\r\n"+head+"\r\nok";closeAfter=true
   case "/truncated":wire="HTTP/1.1 200 OK\r\n"+head+"Content-Length: 5\r\n\r\nok";closeAfter=true
   case "/malformed":wire="HTTP/1.1 200 OK\r\n"+head+"Content-Length: 2\r\nContent-Length: 3\r\n\r\nok";closeAfter=true
   case "/badchunk":wire="HTTP/1.1 200 OK\r\n"+head+"Transfer-Encoding: chunked\r\n\r\nZ\r\n";closeAfter=true
   case "/101":wire="HTTP/1.1 101 Switching Protocols\r\n"+head+"\r\n";closeAfter=true
   case "/surplus":wire="HTTP/1.1 200 OK\r\n"+head+"Content-Length: 2\r\n\r\nokOLD"
   case "/post":if request.Method!="POST"||string(body)!="payload"{panic("POST bytes")};fallthrough
   default:wire="HTTP/1.1 200 OK\r\n"+head+"Content-Length: 2\r\n\r\nok"
   }
   if *mode=="keyupdate-inline"&&order==1 {raw.keyUpdate();manual=true}
   if manual {_,e=raw.Conn.Write(raw.record([]byte(wire),23));if e!=nil{return}} else {
   // A surplus vector is one TLS application record / one byte-stream write.
   if *mode=="framing-fragmented"&&request.URL.Path!="/surplus" {for at:=0;at<len(wire); {n:=min(3,len(wire)-at);_,e=io.WriteString(stream,wire[at:at+n]);if e!=nil{return};at+=n}}else{_,e=io.WriteString(stream,wire);if e!=nil{return}}
   }
   if request.URL.Path=="/A"&&(*mode=="stale"||*mode=="peer-close"||*mode=="partial"||*mode=="separate"||*mode=="keyupdate") {
    waitFile(filepath.Join(*dir,"A.done"))
    if *mode=="stale" {if tcp,ok:=conn.(*net.TCPConn);ok{tcp.SetLinger(0)};conn.Close()} else if *mode=="peer-close" {stream.Close()} else if *mode=="keyupdate"{raw.keyUpdate()} else if secureConnection{wire:=raw.record([]byte("OLD"),23);if *mode=="partial"{wire=wire[:3]};_,e=raw.Conn.Write(wire);must(e)}else{_,e=raw.Conn.Write([]byte("OLD"));must(e)}
    must(os.WriteFile(filepath.Join(*dir,"staged"),[]byte("done"),0600))
    if *mode=="stale"||*mode=="peer-close"{return}
   }
   if closeAfter{return}
  };panic("per-connection fixture request cap")
 }
 accept:=func(conn net.Conn){mu.Lock();connections++;id:=connections;mu.Unlock();if id>32{panic("connection fixture cap")};wg.Add(1);go handle(conn,id)}
 secondDone:=make(chan struct{})
 go func(){defer close(secondDone);for {conn,e:=second.Accept();if e!=nil{return};accept(conn)}}()
 fmt.Println(listener.Addr().String())
 tcp:=listener.(*net.TCPListener)
 until:=time.Now().Add(20*time.Second)
 for time.Now().Before(until) {
  if _,e:=os.Stat(filepath.Join(*dir,"done"));e==nil{break}
  must(tcp.SetDeadline(time.Now().Add(20*time.Millisecond)))
  conn,e:=tcp.Accept();if timeout,ok:=e.(net.Error);ok&&timeout.Timeout(){continue};must(e)
  accept(conn)
 }
 listener.Close();second.Close();<-secondDone;wg.Wait()
 if _,e:=os.Stat(filepath.Join(*dir,"done"));e!=nil{panic("native completion not signalled")}
 mu.Lock();result:=map[string]any{"mode":*mode,"tls":*encrypted,"connections":connections,"requests":len(events),"events":events,"handshake_errors":handshakeErrors,"key_updates":keyUpdates,"client_key_updates":clientUpdates};mu.Unlock()
 encoded,e:=json.Marshal(result);must(e);fmt.Println(string(encoded))
}
type writerFunc func([]byte)(int,error)
func(f writerFunc) Write(p []byte)(int,error){return f(p)}
func waitFile(path string){until:=time.Now().Add(10*time.Second);for time.Now().Before(until){if _,e:=os.Stat(path);e==nil{return};time.Sleep(time.Millisecond)};panic("fixture coordination timeout")}


type readerConn struct {net.Conn;reader *bufio.Reader}
func(c *readerConn)Read(p []byte)(int,error){return c.reader.Read(p)}
func dnsServe(conn net.PacketConn){
 for count:=0;count<256;count++ {var b [4096]byte;n,peer,e:=conn.ReadFrom(b[:]);if e!=nil{return};q:=b[:n];if len(q)<17||binary.BigEndian.Uint16(q[4:6])!=1{continue};at:=12
  for at<len(q)&&q[at]!=0 {size:=int(q[at]);if size>63||at+1+size>=len(q){at=len(q);break};at+=size+1};if at+5>len(q){continue};at++;kind:=binary.BigEndian.Uint16(q[at:at+2]);end:=at+4
  out:=append([]byte{},q[:end]...);out[2]=0x81;out[3]=0x80;out[6]=0;out[7]=0;out[8]=0;out[9]=0;out[10]=0;out[11]=0
  if kind==1{out[7]=1;out=append(out,0xc0,0x0c,0,1,0,1,0,0,0,1,0,4,127,0,0,1)};_,_=conn.WriteTo(out,peer)
 }
}
