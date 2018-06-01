# Encrypt a JWE token::
# ASYMMETRIC KEYS: 
# http://jwcrypto.readthedocs.io/en/latest/jwe.html#examples

from jwcrypto import jwk, jwe
from jwcrypto.common import json_encode, json_decode

import json

public_key = jwk.JWK()
private_key = jwk.JWK.generate(kty='RSA', size=2048)
public_key.import_key(**json_decode(private_key.export_public()))

print("\nPrivate Key used:\n" )
print(json.dumps(json.loads(private_key.export())).replace(", " , ", \n" ))

print("\nPublic Key used:\n")
print(json.dumps(json.loads(public_key.export_public())).replace(", " , ", \n" ))
	

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

# print type(enc)
print("\nEncrypted JWE: \n")
print(json.dumps(json.loads(enc)).replace("," , ",\n" ))



# Decrypting a JWE token on the other end::
jwetoken = jwe.JWE()
jwetoken.deserialize(enc, key=private_key)
payload = jwetoken.payload

# print type(payload)
print ("\n\nDecrypted message on other end: \n" + payload)


### ALTERNATIVE APPROACH
### https://stackoverflow.com/questions/39163000/jwt-encrypting-payload-in-python-jwe?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa


# claims = {
# 'iss': 'http://www.example.com',
# 'sub': 42,
# }
# pub_pem = open("rsa-public-key.json", "r").read()

# pubKey = {'k':\
#            '-----BEGIN PUBLIC KEY-----\n'
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn4EPtAOCc9AlkeQHPzHS
# tgAbgs7bTZLwUBZdR8/KuKPEHLd4rHVTeT+O+XV2jRojdNhxJWTDvNd7nqQ0VEiZ
# QHz/AJmSCpMaJMRBSFKrKb2wqVwGU/NsYOYL+QtiWN2lbzcEe6XC0dApr5ydQLrH
# qkHHig3RBordaZ6Aj+oBHqFEHYpPe7Tpe+OfVfHd1E6cS6M1FZcD1NNLYD5lFHpP
# I9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3+tVTU4fg/3L/vniUFAKw
# uCLqKnS2BYwdq/mzSnbLY7h/qixoR7jig3//kRhuaxwUkRz5iaiQkqgc5gHdrNP5
# zwIDAQAB
# -----END PUBLIC KEY-----'''
#     }

# print pubKey    
# # decrypt on the other end using the private key
# privKey = {'k': 
#     '-----BEGIN RSA PRIVATE KEY-----\n'+\
# '-----END RSA PRIVATE KEY-----'
# }

# eprot = {'alg': "RSA-OAEP", 'enc': "A128CBC-HS256"}
# stringPayload = u'attack at dawn'
# E = jwe.JWE(stringPayload, json_encode(eprot))
# E.add_recipient(pubKey)
# encrypted_token = E.serialize(compact=True)
# E = jwe.JWE()
# E.deserialize(encrypted_token, key=privKey)
# decrypted_payload = E.payload