## JWT – JSON Web Token

While previous parts of JOSE provide a general purpose cryptographic primitives for arbitrary data, JSON Web Token standard is more tied to the [OpenID Connect](https://openid.net/connect/). A JWT object is simply a JSON hash with claims, that is either signed with JWS or encrypted with JWE and serialized using compact serialization. Beware of a terminological quirk - when JWT is used as plaintext in JWE or JWS, it is referred to as nested JWT (rather than signed, or encrypted).

JWT standard defines claims - name/value pair asserting information about subject. The claims include

* `iss` – to identify issuer of the claim
* `sub` – identifying subject of JWT
* `aud` – (audience) identifying intended recipients
* `exp` – to mark expiration time of JWT
* `nbf` – (not before) to mark time before which JWT must be rejected
* `iat` – (issued at) to mark time when JWT was created
* `jti` – (JWT ID) as unique identifier for JWT

While standard mandates what are mandatory values of the claims, all of them are optional to use in a valid JWT. This means applications can use any structure for JWT if it's not intended to use publicly, and for public JWT set of claims is defined and collisions in names are prevented.
