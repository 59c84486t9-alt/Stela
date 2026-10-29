# Independent protocol peer via Python's OpenSSL-backed ssl module.
import socket,ssl,sys,json,pathlib
p=pathlib.Path(__file__).parent/'fixtures'
version,group,kind=sys.argv[1:]
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_2 if version=='12' else ssl.TLSVersion.TLSv1_3
context.set_ecdh_curve('X25519' if group=='x25519' else 'prime256v1')
context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20')
context.load_cert_chain(str(p/(kind+'-leaf.pem')),str(p/(kind+'-key.pem')))
listener=socket.socket();listener.settimeout(5);listener.bind(('127.0.0.1',0));listener.listen(1)
print(listener.getsockname()[1],flush=True)
raw,_=listener.accept();raw.settimeout(5)
with context.wrap_socket(raw,server_side=True) as connection:
 request=b''
 while b'\r\n\r\n' not in request:
  data=connection.recv(4096)
  if not data:raise RuntimeError('truncated client request')
  request+=data
  if len(request)>65536:raise RuntimeError('request capacity')
 if request!=b'GET /source HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n':raise RuntimeError('request mismatch')
 cipher=connection.cipher();protocol=connection.version()
 connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nauthenticated')
 plain=connection.unwrap();plain.close()
 print(json.dumps({'openssl':ssl.OPENSSL_VERSION,'protocol':protocol,'cipher':cipher[0],'group':group,'certificate':kind}),flush=True)
listener.close()
