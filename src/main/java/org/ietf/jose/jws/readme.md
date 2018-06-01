<pre>
Internet Engineering Task Force (IETF)                          M. Jones
Request for Comments: 7515                                     Microsoft
Category: Standards Track                                     J. Bradley
ISSN: 2070-1721                                            Ping Identity
                                                             N. Sakimura
                                                                     NRI
                                                                May 2015


                        JSON Web Signature (JWS)

1.  Introduction

   JSON Web Signature (JWS) represents content secured with digital
   signatures or Message Authentication Codes (MACs) using JSON-based
   [RFC7159] data structures.  The JWS cryptographic mechanisms provide
   integrity protection for an arbitrary sequence of octets.

   Two closely related serializations for JWSs are defined.

    -  JWS Compact Serialization
    -  JWS JSON Serialization

3.  JSON Web Signature (JWS) Overview

   JWS represents digitally signed or MACed content using JSON data
   structures and base64url encoding.  A JWS represents these logical
   values:

   o  JOSE Header
   o  JWS Payload
   o  JWS Signature

3.1.  JWS Compact Serialization Overview

   In the JWS Compact Serialization, no JWS Unprotected Header is used.
   In this case, the JOSE Header and the JWS Protected Header are the
   same.

   In the JWS Compact Serialization, a JWS is represented as the
   concatenation:

      BASE64URL(UTF8(JWS Protected Header)) || '.' ||
      BASE64URL(JWS Payload) || '.' ||
      BASE64URL(JWS Signature)


3.2.  JWS JSON Serialization Overview

   In the JWS JSON Serialization, one or both of the JWS Protected
   Header and JWS Unprotected Header MUST be present.  In this case, the
   members of the JOSE Header are the union of the members of the JWS
   Protected Header and the JWS Unprotected Header values that are
   present.

   In the JWS JSON Serialization, a JWS is represented as a JSON object
   containing some or all of these four members:

   o  "protected", with the value BASE64URL(UTF8(JWS Protected Header))
   o  "header", with the value JWS Unprotected Header
   o  "payload", with the value BASE64URL(JWS Payload)
   o  "signature", with the value BASE64URL(JWS Signature)

7.2.  JWS JSON Serialization

   Two closely related syntaxes are defined for the JWS JSON
   Serialization: a fully general syntax, with which content can be
   secured with more than one digital signature and/or MAC operation,
   and a flattened syntax, which is optimized for the single digital
   signature or MAC case.

7.2.1.  General JWS JSON Serialization Syntax

   The following members are defined for use in top-level JSON objects
   used for the fully general JWS JSON Serialization syntax:

   payload
   signatures
    protected
    header
    signature

   At least one of the "protected" and "header" members MUST be present
   for each signature/MAC computation so that an "alg" Header Parameter
   value is conveyed.

7.2.2.  Flattened JWS JSON Serialization Syntax

   The flattened JWS JSON Serialization syntax is based upon the general
   syntax but flattens it, optimizing it for the single digital
   signature/MAC case.  It flattens it by removing the "signatures"
   member and instead placing those members defined for use in the
   "signatures" array (the "protected", "header", and "signature"
   members) in the top-level JSON object (at the same level as the
   "payload" member).
</pre>