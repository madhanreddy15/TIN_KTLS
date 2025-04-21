openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes

gcc ktls_server.c -o ktls_server -lssl -lcrypto
./ktls_server

gcc ktls_client.c -o ktls_client -lssl -lcrypto
./ktls_client 


To check if KTLS is used , check the contents of /proc/net/tls_stat:
TlsTxSw                         	1
TlsRxSw                         	1