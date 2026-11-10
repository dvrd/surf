package main
import("bufio";"crypto/ecdsa";"crypto/elliptic";"crypto/rand";"crypto/tls";"crypto/x509";"crypto/x509/pkix";"encoding/json";"encoding/pem";"flag";"fmt";"io";"math/big";"net";"net/http";"os";"path/filepath";"strconv";"strings";"sync";"time")
type row struct{ID int `json:"id"`;Connection int `json:"connection"`;Method string `json:"method"`;Path string `json:"path"`;Body string `json:"body"`;TLSVersion uint16 `json:"tls_version"`;ALPN string `json:"alpn"`}
func must(e error){if e!=nil{panic(e)}}
func exists(p string)bool{_,e:=os.Stat(p);return e==nil}
func main(){encrypted:=flag.Bool("tls",false,"");mode:=flag.String("mode","success","");dir:=flag.String("dir","","");flag.Parse();must(os.MkdirAll(*dir,0700))
 listener,e:=net.Listen("tcp4","127.0.0.1:0");must(e);var config *tls.Config
 if *encrypted{key,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);must(e);now:=time.Now();cert:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"owned concurrency peer"},NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour),IPAddresses:[]net.IP{net.ParseIP("127.0.0.1")},IsCA:true,BasicConstraintsValid:true,KeyUsage:x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
 der,e:=x509.CreateCertificate(rand.Reader,cert,cert,&key.PublicKey,key);must(e);must(os.WriteFile(filepath.Join(*dir,"root.pem"),pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),0600));config=&tls.Config{Certificates:[]tls.Certificate{{Certificate:[][]byte{der},PrivateKey:key}},MinVersion:tls.VersionTLS13,MaxVersion:tls.VersionTLS13,NextProtos:[]string{"http/1.1"},SessionTicketsDisabled:true}}
 var mu sync.Mutex;var wg sync.WaitGroup;rows:=[]row{};seen:=map[int]bool{};connections:=0;peak:=0;active:=0;closed:=false;acceptDone:=make(chan struct{})
 go func(){defer close(acceptDone);for{c,e:=listener.Accept();if e!=nil{mu.Lock();end:=closed;mu.Unlock();if !end{panic(e)};return};mu.Lock();connections++;cid:=connections;active++;if active>peak{peak=active};mu.Unlock();wg.Add(1)
 go func(raw net.Conn,id int){defer wg.Done();defer raw.Close();defer func(){mu.Lock();active--;mu.Unlock()}();must(raw.SetDeadline(time.Now().Add(20*time.Second)));var stream net.Conn=raw;version:=uint16(0);alpn:=""
 if config!=nil{t:=tls.Server(raw,config);if e:=t.Handshake();e!=nil{return};s:=t.ConnectionState();version=s.Version;alpn=s.NegotiatedProtocol;if version!=tls.VersionTLS13||alpn!="http/1.1"{panic("authentication protocol")};stream=t}
 reader:=bufio.NewReader(stream);for{request,e:=http.ReadRequest(reader);if e!=nil{return};body,e:=io.ReadAll(io.LimitReader(request.Body,128));must(e);must(request.Body.Close());text:=strings.TrimPrefix(request.URL.Path,"/work/");n,e:=strconv.Atoi(text);must(e);if n<0||n>=64||request.Method!="POST"||string(body)!=text||request.Header.Get("X-Id")!=text{panic("request clone or identity")}
 mu.Lock();if seen[n]{panic("duplicate accepted request")};seen[n]=true;rows=append(rows,row{n,id,request.Method,request.URL.Path,string(body),version,alpn});mu.Unlock()
 head:=fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nX-Connection: %d\r\n\r\n",len(text),id);_,e=io.WriteString(stream,head);if e!=nil{return}
 if *mode=="shutdown"{must(os.WriteFile(filepath.Join(*dir,"held"),[]byte("held"),0600));start:=time.Now();for !exists(filepath.Join(*dir,"release")){if time.Since(start)>15*time.Second{panic("held peer not released")};time.Sleep(time.Millisecond)}}
 if _,e=io.WriteString(stream,text);e!=nil{return}
 }}(c,cid)}}()
 fmt.Println(listener.Addr().String());start:=time.Now();for !exists(filepath.Join(*dir,"done")){if time.Since(start)>20*time.Second{panic("host not done")};time.Sleep(time.Millisecond)}
 mu.Lock();closed=true;mu.Unlock();must(listener.Close());<-acceptDone;wg.Wait();mu.Lock();defer mu.Unlock();if connections>2||peak>2{panic("connection capacity exceeded")};if *mode=="success"&&len(rows)!=64{panic("missing requests")};if *mode=="shutdown"&&len(rows)==0{panic("shutdown had no actual request")};must(json.NewEncoder(os.Stdout).Encode(map[string]any{"requests":rows,"connections":connections,"peak":peak,"tls":*encrypted,"mode":*mode}))
}
