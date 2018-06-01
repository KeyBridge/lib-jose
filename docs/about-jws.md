## JWS – JSON Web Signature

JSON Web Signature standard describes process of creation and validation of datastructure representing signed payload. As example take following string as a payload:

```javascript
{
 "iss":"joe",
 "exp":1300819380,
 "http://example.com/is_root":true
 }
```

Incidentally, this string contains JSON data, but this is not relevant for the signing procedure and it might as well be any data. Before signing, the payload is always converted to base64url encoding:

```
eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLm
NvbS9pc19yb290Ijp0cnVlfQ
```

Additional parameters are associated with each payload. Required parameter is "alg", which denotes the algorithm used for generating a signature (one of the possible values is "none" for unprotected messages). The parameters are included in final JWS in either protected or unprotected header. The data in protected unprotectedHeader is integrity protected and base64url encoded, whereas unprotected unprotectedHeader human readable associated data.

As example, the protected header will contain following data:

```javascript
{"alg":"ES256"}
```

which in base64url encoding look like this:

```eyJhbGciOiJFUzI1NiJ9```

The "ES356" here is identifier for ECDSA signature algorithm using P-256 curve and SHA-256 digest algorithm.

Unprotected header can contain a key id parameter:

```
{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"}
```

The base64url encoded payload and protected header are concatenated with '.' to form a raw data, which is fed to the signature algorithm to produce the final signature.

Finally, the JWS output is serialized using one of JSON or Compact serializations. Compact serialization is simple concatenation of comma separated base64url encoded protected header, payload and signature. JSON serialization is a human readable JSON object, which for the example above would look like this:

```javascript
{
  "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
  "protected":"eyJhbGciOiJFUzI1NiJ9",
  "header":
    {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
     "signature":
     "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
}
```

Such process for generating signature is pretty straightforward, yet still supports some advanced use-cases, such as multiple signatures with separate headers.
