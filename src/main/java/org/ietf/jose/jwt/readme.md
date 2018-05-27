<pre>
Internet Engineering Task Force (IETF)                          M. Jones
Request for Comments: 7519                                     Microsoft
Category: Standards Track                                     J. Bradley
ISSN: 2070-1721                                            Ping Identity
                                                             N. Sakimura
                                                                     NRI
                                                                May 2015


                          JSON Web Token (JWT)

Abstract

   JSON Web Token (JWT) is a compact, URL-safe means of representing
   claims to be transferred between two parties.  The claims in a JWT
   are encoded as a JSON object that is used as the payload of a JSON
   Web Signature (JWS) structure or as the plaintext of a JSON Web
   Encryption (JWE) structure, enabling the claims to be digitally
   signed or integrity protected with a Message Authentication Code
   (MAC) and/or encrypted.

1.  Introduction

   JSON Web Token (JWT) is a compact claims representation format
   intended for space constrained environments such as HTTP
   Authorization headers and URI query parameters.  JWTs encode claims
   to be transmitted as a JSON [RFC7159] object that is used as the
   payload of a JSON Web Signature (JWS) [JWS] structure or as the
   plaintext of a JSON Web Encryption (JWE) [JWE] structure, enabling
   the claims to be digitally signed or integrity protected with a
   Message Authentication Code (MAC) and/or encrypted.  JWTs are always
   represented using the JWS Compact Serialization or the JWE Compact
   Serialization.

   The suggested pronunciation of JWT is the same as the English word
   "jot".

2.  Terminology

   Claim
      A piece of information asserted about a subject.  A claim is
      represented as a name/value pair consisting of a Claim Name and a
      Claim Value.

4.1.  Registered Claim Names

       "iss" (Issuer)
       "sub" (Subject)
       "aud" (Audience)
       "exp" (Expiration Time)
       "nbf" (Not Before)
       "iat" (Issued At)
       "jti" (JWT ID)

7.  Creating and Validating JWTs

7.1.  Creating a JWT

   To create a JWT, the following steps are performed.  The order of the
   steps is not significant in cases where there are no dependencies
   between the inputs and outputs of the steps.

   1.  Create a JWT Claims Set containing the desired claims.
   2.  Let the Message be the octets of the UTF-8 representation of the
       JWT Claims Set.
   3.  Create a JOSE Header containing the desired set of Header
       Parameters.
   4.  Depending upon whether the JWT is a JWS or JWE:
       *  JWT is a JWS: create a JWS with the Message as the JWS Payload.
       *  JWT is a JWE: create a JWE with the Message as the JWE plaintext.
   5.  Return to Step 3 if a nested operation will be performed.
   6.  Otherwise, let the resulting JWT be the JWS or JWE.

7.2.  Validating a JWT

   When validating a JWT, the following steps are performed.  The order
   of the steps is not significant in cases where there are no
   dependencies between the inputs and outputs of the steps.

   1.   Verify that the JWT contains at least one period ('.')
        character.

   2.   Let the Encoded JOSE Header be the portion of the JWT before the
        first period ('.') character.

   3.   Base64url decode the Encoded JOSE Header following the
        restriction that no line breaks, whitespace, or other additional
        characters have been used.

   4.   Verify that the resulting octet sequence is a UTF-8-encoded
        representation of a completely valid JSON object conforming to
        RFC 7159 [RFC7159]; let the JOSE Header be this JSON object.

   5.   Verify that the resulting JOSE Header includes only parameters
        and values whose syntax and semantics are both understood and
        supported or that are specified as being ignored when not
        understood.

   6.   Determine whether the JWT is a JWS or a JWE using any of the
        methods described in Section 9 of [JWE].

   7.   Depending upon whether the JWT is a JWS or JWE, there are two
        cases:

        *  JWT is a JWS: validates as a JWS.

        *  JWT is a JWE: validate as a JWE.

   8.   If the JOSE Header contains a "cty" (content type) value of
        "JWT", then the Message is a JWT that was the subject of nested
        signing or encryption operations.  In this case, return to Step
        1, using the Message as the JWT.

   9.   Otherwise, base64url decode the Message following the
        restriction that no line breaks, whitespace, or other additional
        characters have been used.

   10.  Verify that the resulting octet sequence is a UTF-8-encoded
        representation of a completely valid JSON object conforming to
        RFC 7159 [RFC7159]; let the JWT Claims Set be this JSON object.

   Finally, note that it is an application decision which algorithms may
   be used in a given context.  Even if a JWT can be successfully
   validated, unless the algorithms used in the JWT are acceptable to
   the application, it SHOULD reject the JWT.

8.  Implementation Requirements

   Of the signature and MAC algorithms specified in JSON Web Algorithms
   [JWA], only HMAC SHA-256 ("HS256") and "none" MUST be implemented by
   conforming JWT implementations.

   Support for encrypted JWTs is OPTIONAL.

9.  URI for Declaring that Content is a JWT

   This specification registers the URN
   "urn:ietf:params:oauth:token-type:jwt" for use by applications that
   declare content types using URIs (rather than, for instance, media
   types) to indicate that the content referred to is a JWT.


</pre>