#!/usr/bin/python
# -*- coding: utf-8 -*-


# Sign a JWS token::
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode,json_decode

##  Generate new key - ideally we would read key from file
key = jwk.JWK.generate(kty='oct', size=256)
print ("Generated Key used for signing: \n" +key.export())

# # # # Read PEM key from file - DOESN'T WORK
# # Currently, we are unable to load JWK files
# # Results in following error:
# # '''
# #  File "/usr/local/lib/python2.7/dist-packages/jwcrypto/jwk.py", line 517, in _decode_int
# #     return int(hexlify(base64url_decode(n)), 16)
# # ValueError: invalid literal for int() with base 16: ''
# # '''


# pub_pem = open("rsa-public-key.pem", "rb").read()

# pubKey = {'k':\
#            pub_pem
#     }

# print type(pub_pem)
# print pub_pem

# jwk1 = jwk.JWK() 
# # # print jwk1
# # # print type(jwk1)

# import json

# key = jwk1.import_from_pem(pub_pem, password=None)
# print key
# print type(key)


# # pub_json = open("rsa-public-key.json", "r").read()
# # priv_json = open("rsa-private-key.json", "r").read()
# # key.import_key(**json_decode(priv_json))

# print key
# print type(key)

payload = "Demo Integrity protected message"

jwstoken = jws.JWS(payload.encode('utf-8'))

jwstoken.add_signature(key, None,
                           json_encode({"alg": "HS256"}),
                           json_encode({"kid": key.thumbprint()})
                           )
sig = jwstoken.serialize()
print "\nSigned JWT: \n"+sig


# Verify a JWS token::
jwstoken = jws.JWS()
jwstoken.deserialize(sig)
jwstoken.verify(key)
payload = jwstoken.payload
print ("\nVerified payload at other end:\n" + payload)

# http://jwcrypto.readthedocs.io/en/latest/jws.html