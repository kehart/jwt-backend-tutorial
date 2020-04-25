# JWT Backend Tutorial

## Endpoints

1. POST /signup (handled by signup)
2. POST /login (handled by login)
3. GET /protected (handled by protectedEndpoint)

## Notes on JWTs

### General Info
- JWT stands for JSON Web Token
- JWT is a means of exchanging information between two parties (in payload)
- Digitally signed

### Structure of JWT
{Base64 encoded Header}.{Base64 encoded Payload}.{Signature}
- Header contains __algorithm__ and __token type__ , and before encoding looks like
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```
- The payload can carry claims, which are user and additional data such as token expiry, etc.
- Three types of claims: __Registered__, __Public__, and __Private__
- Before encoding, an example is 
```json
{
  "email": "test@example.com",
  "issuer": "course"
}
```
- The signature is computer from the header, payload, and a secret
- Signature generated by am algorithm
- Digitally signed using a secret string only known to the developer (cannot be decrypted)