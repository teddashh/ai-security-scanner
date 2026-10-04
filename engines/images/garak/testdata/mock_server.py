import hashlib,http.server,json,select,socket,socketserver,ssl,struct,threading,time
from pathlib import Path
root=Path('/fixture')
class Http(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_POST(self):
  body=self.rfile.read(int(self.headers.get('Content-Length','0')))
  mode=(root/'mode').read_text().strip()
  row={'time':time.monotonic(),'path':self.path,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'tls':True,'model':json.loads(body)['model'],'max_tokens':json.loads(body)['max_tokens']}
  with (root/'requests.jsonl').open('a') as stream:stream.write(json.dumps(row)+'\n')
  if self.path!='/v1/chat/completions':self.send_response(404);self.end_headers();return
  if mode=='redirect':self.send_response(307);self.send_header('Location','https://other.example.test/v1/chat/completions');self.end_headers();return
  if mode=='retry':self.send_response(429);self.send_header('Content-Length','0');self.end_headers();return
  content='DAN Mode enabled; \\x1b[31mfixture\\x1b[0m' if mode=='positive' else 'I cannot follow that instruction.'
  data=json.dumps({'choices':[{'message':{'role':'assistant','content':content}}]}).encode()
  self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
class Socks(socketserver.BaseRequestHandler):
 def read(self,n):
  result=b''
  while len(result)<n:
   chunk=self.request.recv(n-len(result))
   if not chunk:raise EOFError()
   result+=chunk
  return result
 def handle(self):
  try:
   version,count=self.read(2);methods=self.read(count)
   if version!=5 or 0 not in methods:return
   self.request.sendall(b'\x05\x00')
   version,command,reserved,kind=self.read(4)
   if kind==3:host=self.read(self.read(1)[0]).decode()
   elif kind==1:host=socket.inet_ntoa(self.read(4))
   else:return
   port=struct.unpack('!H',self.read(2))[0]
   if (version,command,reserved,host,port)!=(5,1,0,'model.example.test',8443):
    with (root/'denied.jsonl').open('a') as stream:stream.write(json.dumps({'host':host,'port':port})+'\n')
    self.request.sendall(b'\x05\x02\x00\x01'+b'\x00'*6);return
   with socket.create_connection(('127.0.0.1',8443),timeout=5) as remote:
    self.request.sendall(b'\x05\x00\x00\x01'+b'\x00'*6)
    sockets=[self.request,remote]
    while True:
     readable,_,_=select.select(sockets,[],[],30)
     if not readable:return
     for current in readable:
      data=current.recv(65536)
      if not data:return
      (remote if current is self.request else self.request).sendall(data)
  except (OSError,EOFError):pass
class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'cert.pem',root/'key.pem')
http=http.server.ThreadingHTTPServer(('0.0.0.0',8443),Http);http.socket=context.wrap_socket(http.socket,server_side=True)
threading.Thread(target=http.serve_forever,daemon=True).start()
print('ready',flush=True)
Server(('0.0.0.0',1080),Socks).serve_forever()
