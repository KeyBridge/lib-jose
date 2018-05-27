<pre>
Internet Engineering Task Force (IETF)                          M. Jones
Request for Comments: 7517                                     Microsoft
Category: Standards Track                                       May 2015
ISSN: 2070-1721


                           JSON Web Key (JWK)

1.  Introduction

   A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) [RFC7159]
   data structure that represents a cryptographic key.  This
   specification also defines a JWK Set JSON data structure that
   represents a set of JWKs.

3.  Example JWK

   This section provides an example of a JWK.  The following example JWK
   declares that the key is an Elliptic Curve [DSS] key, it is used with
   the P-256 Elliptic Curve, and its x and y coordinates are the
   base64url-encoded values shown.  A key identifier is also provided
   for the key.

     {"kty":"EC",
      "crv":"P-256",
      "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "kid":"Public key used in JWS spec Appendix A.3 example"
     }

4.  JSON Web Key (JWK) Format

   A JWK is a JSON object that represents a cryptographic key.  The
   members of the object represent properties of the key, including its
   value.

     "kty" (Key Type)
     "use" (Public Key Use)
     "key_ops" (Key Operations)
     "alg" (Algorithm)
     "kid" (Key ID)
     "x5u" (X.509 URL)
     "x5c" (X.509 Certificate Chain)
     "x5t" (X.509 Certificate SHA-1 Thumbprint)
     "x5t#S256" (X.509 Certificate SHA-256 Thumbprint)

</pre>