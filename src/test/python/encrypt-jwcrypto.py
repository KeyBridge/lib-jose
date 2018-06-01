'''
Encrypt or Decrypt a JWE token::
with imported or generated asymmetric keys: 
based on http://jwcrypto.readthedocs.io/en/latest/jwe.html#examples
'''

from jwcrypto import jwk, jwe
from jwcrypto.common import json_encode, json_decode



### GENERATE CUSTOM KEYS - ALTERNATIVE 1
# public_key = jwk.JWK()
# private_key = jwk.JWK.generate(kty='RSA', size=2048)
# public_key.import_key(**json_decode(private_key.export_public()))




### IMPORT CUSTOM KEYS - JSON - ALTERNATIVE 2
priv_json = open("keys/rsa-private-key.json", "rb").read().replace('"use": "sig",','') #ignore use: sig because we are using use: enc

print("\nImporting following Private Key:\n" )
print(priv_json.replace(", " , ", \n" ))
print("--------")


pub_json = open("keys/rsa-public-key.json", "rb").read().replace('"use": "sig",','') #ignore use: sig because we are using use: enc

print("\nImporting following Public Key:\n" )
print(pub_json.replace(", " , ", \n" ))
print("--------")


private_key = jwk.JWK()
private_key.import_key(**json_decode(priv_json))

public_key = jwk.JWK()
public_key.import_key(**json_decode(pub_json))





### IMPORT CUSTOM KEYS - PEM  - ALTERNATIVE 3

# pub_pem = open("keys/rsa-public-key.pem", "rb").read()
# print("\nTrying to import following Public Key PEM:\n" )
# print(pub_pem)
# print("--------")

# priv_pem = open("keys/rsa-private-key.pem", "rb").read()
# print("\nTrying to import following Private Key PEM:\n" )
# print(priv_pem)
# print("--------")

# public_key = jwk.JWK()
# private_key = jwk.JWK()
# private_key.import_from_pem(priv_pem)
# public_key.import_from_pem(pub_pem)




### ENCRYPTING USING PUBLIC KEY
print("\n------\nENCRYPTING USING PUBLIC KEY:\n" )

print("\nPrivate Key used:\n" )
print(private_key.export().replace("," , ",\n" ))

print("\n\nPublic Key used:\n")
print(public_key.export_public().replace("," , ",\n" ))
	

payload = "Demo Encrypted message"

protected_header = {
        "alg": "RSA-OAEP-256",
        "enc": "A256CBC-HS512",
        "typ": "JWE",
        "kid": public_key.thumbprint(),
    }

jwetoken = jwe.JWE(payload.encode('utf-8'),
                       recipient=public_key,
                       protected=protected_header)

enc = jwetoken.serialize()

print("\n\nEncrypted JWE: \n")
print(enc.replace("," , ",\n" ))






### DECRYPTING A JWE TOKEN ON THE OTHER END USING PRIVATE KEY::
print("\n\n------\nDECRYPTING USING PRIVATE KEY:\n" )

jwetoken = jwe.JWE()
jwetoken.deserialize(enc, key=private_key)
payload = jwetoken.payload

# print type(payload)
print ("Decrypted message on other end: \n" + payload)