<pre>
Internet Engineering Task Force (IETF)                          M. Jones
Request for Comments: 7516                                     Microsoft
Category: Standards Track                                  J. Hildebrand
ISSN: 2070-1721                                                    Cisco
                                                                May 2015


                       JSON Web Encryption (JWE)

Abstract

   JSON Web Encryption (JWE) represents encrypted content using
   JSON-based data structures.  Cryptographic algorithms and identifiers
   for use with this specification are described in the separate JSON
   Web Algorithms (JWA) specification and IANA registries defined by
   that specification.  Related digital signature and Message
   Authentication Code (MAC) capabilities are described in the separate
   JSON Web Signature (JWS) specification.


1.  Introduction

   JSON Web Encryption (JWE) represents encrypted content using JSON-
   based data structures [RFC7159].  The JWE cryptographic mechanisms
   encrypt and provide integrity protection for an arbitrary sequence of
   octets.

   Two closely related serializations for JWEs are defined.  The JWE
   Compact Serialization is a compact, URL-safe representation intended
   for space constrained environments such as HTTP Authorization headers
   and URI query parameters.  The JWE JSON Serialization represents JWEs
   as JSON objects and enables the same content to be encrypted to
   multiple parties.  Both share the same cryptographic underpinnings.

   Cryptographic algorithms and identifiers for use with this
   specification are described in the separate JSON Web Algorithms (JWA)
   [JWA] specification and IANA registries defined by that
   specification.  Related digital signature and MAC capabilities are
   described in the separate JSON Web Signature (JWS) [JWS]
   specification.

3.  JSON Web Encryption (JWE) Overview

   JWE represents encrypted content using JSON data structures and
   base64url encoding.  These JSON data structures MAY contain
   whitespace and/or line breaks before or after any JSON values or
   structural characters, in accordance with Section 2 of RFC 7159
   [RFC7159].  A JWE represents these logical values (each of which is
   defined in Section 2):

   o  JOSE Header
   o  JWE Encrypted Key
   o  JWE Initialization Vector
   o  JWE AAD
   o  JWE Ciphertext
   o  JWE Authentication Tag

   For a JWE, the JOSE Header members are the union of the members of
   these values (each of which is defined in Section 2):

   o  JWE Protected Header
   o  JWE Shared Unprotected Header
   o  JWE Per-Recipient Unprotected Header

   JWE utilizes authenticated encryption to ensure the confidentiality
   and integrity of the plaintext and the integrity of the JWE Protected
   Header and the JWE AAD.

3.1.  JWE Compact Serialization Overview

   In the JWE Compact Serialization, no JWE Shared Unprotected Header or
   JWE Per-Recipient Unprotected Header are used.  In this case, the
   JOSE Header and the JWE Protected Header are the same.

3.2.  JWE JSON Serialization Overview

   In the JWE JSON Serialization, one or more of the JWE Protected
   Header, JWE Shared Unprotected Header, and JWE Per-Recipient
   Unprotected Header MUST be present.  In this case, the members of the
   JOSE Header are the union of the members of the JWE Protected Header,
   JWE Shared Unprotected Header, and JWE Per-Recipient Unprotected
   Header values that are present.

   In the JWE JSON Serialization, a JWE is represented as a JSON object
   containing some or all of these eight members:

      "protected", with the value BASE64URL(UTF8(JWE Protected Header))
      "unprotected", with the value JWE Shared Unprotected Header
      "header", with the value JWE Per-Recipient Unprotected Header
      "encrypted_key", with the value BASE64URL(JWE Encrypted Key)
      "iv", with the value BASE64URL(JWE Initialization Vector)
      "ciphertext", with the value BASE64URL(JWE Ciphertext)
      "tag", with the value BASE64URL(JWE Authentication Tag)
      "aad", with the value BASE64URL(JWE AAD)

</pre>
