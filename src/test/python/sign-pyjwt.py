'''
This script signs a JWT with private key
and verifies the JWS with public key

Based on https://gist.github.com/jpf/1e860e5ea70c0a70fd5e
'''

print ("SIGNING USING PRIVATE KEY:\n")

### IMPORT CUSTOM KEYS - PEM  - ALTERNATIVE 3
priv_pem = open("keys/rsa-private-key.pem", "rb").read()
print("\nImporting following Private Key PEM:\n" )
print(priv_pem)
print("--------")


key = priv_pem

claim = {'test': "hello"}


### SIGNING USING PRIVATE KEY
import jwt
token = jwt.encode(
    claim,
    key,
    algorithm='RS256')
# return token
print ("\nSigned message using public key is:\n")
print (token)

print("----------")




### VERIFYING USING PUBLIC KEY
print ("\nVERIFYING USING PUBLIC KEY:")

pub_pem = open("keys/rsa-public-key.pem", "rb").read()
print("\nImporting following Public Key PEM:\n" )
print(pub_pem)
print("--------")

key = pub_pem

import jwt
print ("\nVerified/decoded message is:\n")
print jwt.decode(token, key, algorithms=['RS256'])
# return jwt.decode(token, key, algorithms=['RS256'])