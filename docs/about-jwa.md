## JWA – JSON Web Algorithms

JSON Web Algorithms defines algorithms and their identifiers to be used in JWS and JWE. The three parameters that specify algorithms are "alg" for JWS, "joseAlgorithmName" and "enc" for JWE.

 * **enc**  
      A128CBC-HS256, A192CBC-HS384, A256CBC-HS512 (AES in CBC with HMAC), 
      A128GCM, A192GCM, A256GCM

 * **"alg" for JWS**   
      HS256, HS384, HS512 (HMAC with SHA), 
      RS256, RS384, RS512 (RSASSA-PKCS-v1_5 with SHA), 
      ES256, ES384, ES512 (ECDSA with SHA), 
      PS256, PS384, PS512 (RSASSA-PSS with SHA for digest and MGF1)

 * **"alg" for JWE**  
      RSA1_5, RSA-OAEP, RSA-OAEP-256, 
      A128KW, A192KW, A256KW (AES Keywrap), 
      dir (direct encryption), 
      ECDH-ES (EC Diffie Hellman Ephemeral+Static key agreement), 
      ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW (with AES Keywrap), 
      A128GCMKW, A192GCMKW, A256GCMKW (AES in GCM Keywrap), 
      PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW 
      (PBES2 with HMAC SHA and AES keywrap)

On the first look the wealth of choice for "alg" in JWE is balanced by just two options for "enc". Thanks to "enc" and "alg" being separate, algorithms suitable for encrypting cryptographic key and content can be separately defined. AES Keywrap scheme defined in RFC 3394 is a preferred way to protect cryptographic key. The scheme uses fixed value of IV, which is checked after decryption and provides integrity protection without making the encrypted key longer (by adding IV and authentication tag). But here`s a catch - while A128KW refers to AES Keywrap algorithm as defined in RFC 3394, word "keywrap" in A128GCMKW is used in a more general sense as synonym to encryption, so it denotes simple encryption of key with AES in GCM mode.
