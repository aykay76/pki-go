openssl genrsa -out server.key 2048

openssl req -new -key server.key -out server.csr


