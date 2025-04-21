openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes

gcc server_tls.c -o server_tls
./server_tls

gcc client_tls.c -o client_tls
./client_tls