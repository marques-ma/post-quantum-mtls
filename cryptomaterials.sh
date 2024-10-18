#!/bin/bash

# Set directory paths
CA_DIR="ca"
SERVER_DIR="server"
CLIENT_DIR="client"

# Set common names
SERVER_CN="BR-SeRvEr"
CLIENT_CN="Special-client"

# Create directories if they do not exist
mkdir -p "$CA_DIR" "$SERVER_DIR" "$CLIENT_DIR"

# Generate a private key for the CA using ECDSA
openssl ecparam -name prime256v1 -genkey -noout -out "$CA_DIR/ca.key"

# Generate the CA certificate
openssl req -x509 -new -nodes -key "$CA_DIR/ca.key" -sha256 -days 365 -out "$CA_DIR/ca.crt" -subj "/CN=MySelfSignedCA"

# Generate server's private key using ECDSA
openssl ecparam -name prime256v1 -genkey -noout -out "$SERVER_DIR/server.key"

# Generate server CSR
openssl req -new -key "$SERVER_DIR/server.key" -out "$SERVER_DIR/server.csr" -subj "/C=US/ST=California/L=San Francisco/O=MyOrganization/OU=IT Department/CN=$SERVER_CN"

# Sign server certificate with the CA
openssl x509 -req -in "$SERVER_DIR/server.csr" -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial -out "$SERVER_DIR/server.crt" -days 365 -sha256

# Generate client's private key using ECDSA
openssl ecparam -name prime256v1 -genkey -noout -out "$CLIENT_DIR/client.key"

# Generate client CSR
openssl req -new -key "$CLIENT_DIR/client.key" -out "$CLIENT_DIR/client.csr" -subj "/C=US/ST=California/L=San Francisco/O=MyOrganization/OU=IT Department/CN=$CLIENT_CN"

# Sign client certificate with the CA
openssl x509 -req -in "$CLIENT_DIR/client.csr" -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial -out "$CLIENT_DIR/client.crt" -days 365 -sha256

# Clean up CSR files
rm "$SERVER_DIR/server.csr" "$CLIENT_DIR/client.csr"

# Output completion message
echo "Certificates and keys have been generated:"
echo "CA Certificate: $CA_DIR/ca.crt"
echo "CA Key: $CA_DIR/ca.key"
echo "Server Certificate: $SERVER_DIR/server.crt"
echo "Server Key: $SERVER_DIR/server.key"
echo "Client Certificate: $CLIENT_DIR/client.crt"
echo "Client Key: $CLIENT_DIR/client.key"