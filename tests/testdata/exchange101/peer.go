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
 "encoding/hex"
 "encoding/json"
 "encoding/pem"
 "flag"
 "fmt"
 "io"
 "math/big"
 "net"
 "net/http"
 "os"
 "path/filepath"
 "strings"
 "time"
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
func main(){
 mode:=flag.String("mode","healthy","literal schedule");encrypted:=flag.Bool("tls",false,"TLS13");dir:=flag.String("dir","","fixture directory");flag.Parse()
 must(os.MkdirAll(*dir,0700))
 listener,e:=net.Listen("tcp4","127.0.0.1:0");must(e);defer listener.Close()
 var config *tls.Config
 if *encrypted {
  key,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);must(e)
  template:=&x509.Certificate{SerialNumber:big.NewInt(101),Subject:pkix.Name{CommonName:"localhost"},DNSNames:[]string{"localhost"},NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour),KeyUsage:x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,BasicConstraintsValid:true,IsCA:true,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
  der,e:=x509.CreateCertificate(rand.Reader,template,template,&key.PublicKey,key);must(e)
  must(os.WriteFile(filepath.Join(*dir,"root.pem"),pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),0600))
  config=&tls.Config{Certificates:[]tls.Certificate{{Certificate:[][]byte{der},PrivateKey:key}},MinVersion:tls.VersionTLS13,MaxVersion:tls.VersionTLS13,SessionTicketsDisabled:true,NextProtos:[]string{"http/1.1"},CipherSuites:[]uint16{tls.TLS_AES_128_GCM_SHA256}}
 }
 fmt.Println(listener.Addr().String())
 conn,e:=listener.Accept();must(e);defer conn.Close();must(conn.SetDeadline(time.Now().Add(12*time.Second)))
 raw:=&records{Conn:conn};var stream net.Conn=raw
 if *encrypted {
  config.KeyLogWriter=writerFunc(func(p []byte)(int,error){fields:=strings.Fields(string(p));if len(fields)==3&&fields[0]=="SERVER_TRAFFIC_SECRET_0" {raw.secret,e=hex.DecodeString(fields[2]);must(e)};if len(fields)==3&&fields[0]=="CLIENT_TRAFFIC_SECRET_0" {raw.clientSecret,e=hex.DecodeString(fields[2]);must(e)};return len(p),nil})
  secure:=tls.Server(raw,config);must(secure.Handshake());if secure.ConnectionState().CipherSuite!=tls.TLS_AES_128_GCM_SHA256 {panic("oracle requires AES128GCM/SHA256")};stream=secure
 }
 reader:=bufio.NewReader(stream)
 request,e:=http.ReadRequest(reader);must(e);body,e:=io.ReadAll(io.LimitReader(request.Body,1<<20));must(e);must(request.Body.Close())
 if request.URL.Path!="/A" {panic("first request is not A")}
 response:=[]byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-Sequence: A\r\n\r\nA")
 manual:=false
 if *mode=="keyupdate-inline" {if !*encrypted{panic("TLS required")};raw.keyUpdate();manual=true}
 send:=func(p []byte){var n int;var err error;if manual {n,err=raw.Conn.Write(raw.record(p,23));if err==nil&&n==0{panic("zero write")}}else {_,err=stream.Write(p)};must(err)}
 if *mode=="same-read" {response=append(response,[]byte("OLD")...)}
 if *mode=="fragmented" {for _,b:=range response {send([]byte{b})}}else{send(response)}
 switch *mode {
 case "separate","partial","keyupdate":
  // Wait until the native consumer has completed A before placing old bytes.
  waitFile(filepath.Join(*dir,"A.done"))
  if *mode=="keyupdate" {raw.keyUpdate();manual=true} else if *encrypted {
   wire:=raw.record([]byte("OLD"),23)
   if *mode=="partial" {wire=wire[:3]}
   _,e=raw.Conn.Write(wire);must(e)
  } else {_,e=raw.Conn.Write([]byte("OLD"));must(e)}
 case "close": waitFile(filepath.Join(*dir,"A.done"));must(conn.Close())
 }
 must(os.WriteFile(filepath.Join(*dir,"staged"),[]byte(*mode),0600))
 count:=1
 if *mode=="healthy"||*mode=="fragmented"||*mode=="keyupdate-inline" {
  second,e:=http.ReadRequest(reader);must(e);if second.URL.Path!="/B"{panic("second request not B")};_,e=io.Copy(io.Discard,second.Body);must(e);must(second.Body.Close());count++
  send([]byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-Sequence: B\r\n\r\nB"))
 } else {
  // Retirement must not send B on a contaminated stream.
  var one [1]byte;n,err:=stream.Read(one[:]);if n!=0 {panic("retired stream accepted B bytes")};if err==nil{panic("no terminal peer read")}
 }
 result:=map[string]any{"mode":*mode,"tls":*encrypted,"requests":count,"first_body_bytes":len(body),"application_records":raw.encrypted,"manual_rfc8446":manual||*mode=="partial"||*mode=="separate","key_updates":raw.updates,"client_key_updates":raw.clientUpdates,"manual_sequences":raw.manualSequences}
 encoded,e:=json.Marshal(result);must(e);fmt.Println(string(encoded))
}
type writerFunc func([]byte)(int,error)
func(f writerFunc) Write(p []byte)(int,error){return f(p)}
func waitFile(path string){until:=time.Now().Add(10*time.Second);for time.Now().Before(until){if _,e:=os.Stat(path);e==nil{return};time.Sleep(time.Millisecond)};panic("fixture coordination timeout")}
