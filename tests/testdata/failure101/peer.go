package main

import (
 "bufio"
 "encoding/json"
 "flag"
 "fmt"
 "io"
 "net"
 "net/http"
 "os"
 "path/filepath"
 "sync"
 "time"
)
type event struct { Connection int `json:"connection"`; Path string `json:"path"`; Body string `json:"body"` }
func main(){
 dir:=flag.String("dir","","barrier directory");flag.Parse();if *dir==""{panic("directory required")};if err:=os.MkdirAll(*dir,0700);err!=nil{panic(err)}
 listener,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{panic(err)};defer listener.Close();fmt.Println(listener.Addr())
 var mu sync.Mutex;events:=[]event{};var wg sync.WaitGroup
 go func(){defer listener.Close();until:=time.Now().Add(15*time.Second);for time.Now().Before(until){if _,err:=os.Stat(filepath.Join(*dir,"done"));err==nil{return};time.Sleep(time.Millisecond)}}()
 count:=0
 for {conn,err:=listener.Accept();if err!=nil{break};count++;if count>4{panic("connection bound")};wg.Add(1);go func(id int,c net.Conn){defer wg.Done();defer c.Close();c.SetDeadline(time.Now().Add(10*time.Second));reader:=bufio.NewReader(c)
  request,err:=http.ReadRequest(reader);if err!=nil{return};body,err:=io.ReadAll(io.LimitReader(request.Body,1025));if err!=nil{panic(err)};request.Body.Close();if len(body)>1024{panic("body bound")}
  mu.Lock();events=append(events,event{id,request.URL.Path,string(body)});mu.Unlock()
  if request.URL.Path=="/A" {if err:=os.WriteFile(filepath.Join(*dir,"A.received"),[]byte("ready"),0600);err!=nil{panic(err)};until:=time.Now().Add(8*time.Second);for{if _,err:=os.Stat(filepath.Join(*dir,"release"));err==nil{break};if time.Now().After(until){panic("release timeout")};time.Sleep(time.Millisecond)}
   io.WriteString(c,"HTTP/1.1 307 Temporary Redirect\r\nContent-Length: 0\r\nLocation: /dir/../final\r\n\r\n")
  }else if request.URL.Path=="/final"{io.WriteString(c,"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nX-Connection: 2\r\nConnection: close\r\n\r\nresponse")}else{panic("unexpected request")}
 }(count,conn)}
 wg.Wait();mu.Lock();defer mu.Unlock();json.NewEncoder(os.Stdout).Encode(map[string]any{"connections":count,"events":events})
}
