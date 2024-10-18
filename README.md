# Proof of concept of a mTLS connection using an Hybrid approach (ECDH + Kyber)  

usage:  
on server side:  
go run server-tls.go <port> <server-cert> <server.key>  

on client side:  
go run clien-tls.go <host> <port>  

expected result:  
1 - both sides uses dummy certs and private keys to stablish an mTLS connection.  
2 - They uses ECDH and Kyber512 to exchange and define a shared key, used to encrypt and decrypt the messages.
