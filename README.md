# Proof of concept of a mTLS connection using an Hybrid approach (ECDH + Kyber)

usage:
on server side:
go run server_kem.go <port>

on client side: 
go run client_kem.go <host> <port>

expected result:
both sides can create a shared key and use it to encrypt/decrypt the communication
