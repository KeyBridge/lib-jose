## JWK – JSON Web Key

JSON Web Key is a data structure representing a cryptographic key with both the cryptographic data and other attributes, such as key usage.

```javascript
{ 
  "kty":"EC",
  "crv":"P-256",
  "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
  "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
  "use":"enc",
  "kid":"1"
}
```

Mandatory "kty" key type parameter describes the cryptographic algorithm associated with the key. Depending on the key type, other parameters might be used - as shown in the example elliptic curve key would contain "crv" parameter identifying the curve, "x" and "y" coordinates of point, optional "use" to denote intended usage of the key and "kid" as key ID. The specification now describes three key types: "EC" for Elliptic Curve, "RSA" for, well, RSA, and "oct" for octet sequence denoting the shared symmetric key.
