gcc ktls_server.c -o ktls_server
./ktls_server

gcc ktls_client.c -o ktls_client
./ktls_client 


To check if KTLS is used , check the contents of /proc/net/tls_stat:
TlsTxSw                         	1
TlsRxSw                         	1