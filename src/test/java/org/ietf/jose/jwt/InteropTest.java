package org.ietf.jose.jwt;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.ietf.TestFileReader;
import org.ietf.jose.jwa.JweEncryptionAlgorithmType;
import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.jwe.JsonWebEncryption;
import org.ietf.jose.jwe.JweDecryptor;
import org.ietf.jose.jwe.encryption.Encrypter;
import org.ietf.jose.jwk.JsonWebKey;
import org.ietf.jose.jwk.key.RsaPrivateJwk;
import org.ietf.jose.jwk.key.RsaPublicJwk;
import org.ietf.jose.jws.JsonWebSignature;
import org.ietf.jose.jws.JwsBuilder;
import org.ietf.jose.jws.SignatureValidator;
import org.ietf.jose.util.JsonMarshaller;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 29/05/2018
 */
public class InteropTest {

  @Test
  public void jwkInteropTest() throws Exception {
//    RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);

//org.jose4j.lang.InvalidKeyException:
// An RSA key of size 2048 bits or larger MUST be used with the all JOSE RSA algorithms (given key was only 1024 bits).
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    KeyPair kp = keyPairGenerator.generateKeyPair();

    // Give the JWK a Key ID (kid), which is just the polite thing to do
//    rsaJsonWebKey.setKeyId("k1");
    // Create the Claims, which will be the content of the JWT
    org.jose4j.jwt.JwtClaims claims = new org.jose4j.jwt.JwtClaims();
    claims.setIssuer("Issuer");  // who creates the token and signs it
    claims.setAudience("Audience"); // to whom the token is intended to be sent
    claims.setExpirationTimeMinutesInTheFuture(10); // time when the token will expire (10 minutes from now)
    claims.setGeneratedJwtId(); // a unique identifier for the token
    claims.setIssuedAtToNow();  // when the token was issued/created (now)
    claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
    claims.setSubject("subject"); // the subject/principal is whom the token is about
    claims.setClaim("email", "mail@example.com"); // additional claims/attributes about the subject can be added
    List<String> groups = Arrays.asList("group-one", "other-group", "group-three");
    claims.setStringListClaim("groups", groups); // multi-valued claims work too and will end up as a JSON array

    // A JWT is a JWS and/or a JWE with JSON claims as the payload.
    // In this example it is a JWS so we create a JsonWebSignature object.
    org.jose4j.jws.JsonWebSignature jws = new org.jose4j.jws.JsonWebSignature();

    // The payload of the JWS is JSON content of the JWT Claims
    jws.setPayload(claims.toJson());

    // The JWT is signed using the private key
    jws.setKey(kp.getPrivate());

    // Set the Key ID (kid) header because it's just the polite thing to do.
    // We only have one key in this example but a using a Key ID helps
    // facilitate a smooth key rollover process
    jws.setKeyIdHeaderValue("k1");

    // Set the signature algorithm on the JWT/JWS that will integrity protect the claims
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

    // Sign the JWS and produce the compact serialization or the complete JWT/JWS
    // representation, which is a string consisting of three dot ('.') separated
    // base64url-encoded parts in the form Header.Payload.Signature
    // If you wanted to encrypt it, you can simply set this jwt as the payload
    // of a JsonWebEncryption object and set the cty (Content Type) header to "jwt".
    String jwt = jws.getCompactSerialization();

    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
      .setRequireExpirationTime() // the JWT must have an expiration time
      .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
      .setRequireSubject() // the JWT must have a subject claim
      .setExpectedIssuer("Issuer") // whom the JWT needs to have been issued by
      .setExpectedAudience("Audience") // to whom the JWT is intended for
      .setVerificationKey(kp.getPublic()) // verify the signature with the public key
      .setJwsAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given context
        new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, // which is only RS256 here
                                 AlgorithmIdentifiers.RSA_USING_SHA256)).build();

    org.jose4j.jwt.JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
    System.out.println("JWT validation succeeded! " + jwtClaims);

    // Now you can do something with the JWT. Like send it to some other party
    // over the clouds and through the interwebs.
    System.out.println("jose4j JWT: " + jwt);

    JwtReader reader = JwtReader.readCompactForm(jwt);
    assertEquals(JwtReader.Type.Signed, reader.getType());
    JsonWebSignature jwsDecoded = reader.getJsonWebSignature();
    System.out.println(jwsDecoded);

    assertTrue(SignatureValidator.isValid(jwsDecoded.getSignatures().get(0), kp.getPublic()));

    JwtClaims claimsDecoded = JwtClaims.fromJson(jwsDecoded.getStringPayload());

    assertEquals(claims.getIssuer(), claimsDecoded.getIssuer());
    assertEquals(claims.getSubject(), claimsDecoded.getSubject());
    assertEquals(claims.getAudience().get(0), claimsDecoded.getAudience());
    assertEquals(Instant.ofEpochSecond(claims.getExpirationTime().getValue()), claimsDecoded.getExpirationTime());
    assertEquals(Instant.ofEpochSecond(claims.getNotBefore().getValue()), claimsDecoded.getNotBefore());
    assertEquals(Instant.ofEpochSecond(claims.getIssuedAt().getValue()), claimsDecoded.getIssuedAt());
    assertEquals(claims.getJwtId(), claimsDecoded.getJwtId());

    JwtClaims joseClaims = new JwtClaims();
    joseClaims.setIssuer("Issuer");
    joseClaims.setAudience("Audience");
    joseClaims.setExpirationTime(Instant.ofEpochSecond(claims.getExpirationTime().getValue()));
    joseClaims.setNotBefore(Instant.ofEpochSecond(claims.getNotBefore().getValue()));
    joseClaims.setIssuedAt(Instant.ofEpochMilli(claims.getIssuedAt().getValue()));
    joseClaims.setJwtId(claims.getJwtId());
    joseClaims.setSubject(claims.getSubject());

    String joseClaimsJson = joseClaims.toJson();
    System.out.println("lib-jose Claims:" + joseClaimsJson);
//    JwsBuilder builder = JwsBuilder.getInstance()
//        .withStringPayload(claims.toJson())
//        .sign(kp.getPrivate(), JwsAlgorithmType.RS256, "k1");

    org.jose4j.jwt.JwtClaims jwtClaims2 = jwtConsumer.processToClaims(jwt);
    System.out.println("JWT validation succeeded! " + jwtClaims2);
  }

  @Test
  public void jwkEncryptedTest() throws Exception {
    Encrypter joseEncrypter = JweEncryptionAlgorithmType.A128CBC_HS256.getEncrypter();
    SecretKey key = (SecretKey) joseEncrypter.generateKey();

//    KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    // Create a new Json Web Encryption object
    org.jose4j.jwe.JsonWebEncryption senderJwe = new org.jose4j.jwe.JsonWebEncryption();

    // The plaintext of the JWE is the message that we want to encrypt.
    senderJwe.setPlaintext("hi");
//    senderJwe.setPlaintext("hi".getBytes(StandardCharsets.UTF_8));

    // Set the "alg" header, which indicates the key management mode for this JWE.
    // In this example we are using the direct key management mode, which means
    // the given key will be used directly as the content encryption key.
    senderJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A256KW);

    // Set the "enc" header, which indicates the content encryption algorithm to be used.
    // This example is using AES_128_CBC_HMAC_SHA_256 which is a composition of AES CBC
    // and HMAC SHA2 that provides authenticated encryption.
    senderJwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);

    // Set the key on the JWE. In this case, using direct mode, the key will used directly as
    // the content encryption key. AES_128_CBC_HMAC_SHA_256, which is being used to encrypt the
    // content requires a 256 bit key.
    senderJwe.setKey(key);

    String jose4jecryptedCompact = senderJwe.getCompactSerialization();

    JsonWebEncryption joseJwe = JsonWebEncryption.fromCompactForm(jose4jecryptedCompact);
    JweDecryptor.DecryptionResult result = JweDecryptor.createFor(joseJwe)
      .decrypt(key);
    assertEquals("hi", result.getAsString());
  }

  @Test
  public void signedJwtHmacTest() throws Exception {
    String jwt
           = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsYXN0bmFtZSI6IlJhamthcm5pa2FyIiwiZmlyc3RuYW1lIjoiTmlyYWphbiJ9.9ioIwAcjATPumTWU_Ml6W0ngCx6T4IX8MUgVr3FPD-Q";
    JsonWebSignature jws = JsonWebSignature.fromCompactForm(jwt);
    JwtClaims claims = JwtClaims.fromJson(jws.getStringPayload());
    System.out.println(claims);
    System.out.println(jws.getStringPayload());
    boolean valid = SignatureValidator.isValid(jws.getSignatures().get(0), "secretpassword".getBytes());
    System.out.println(valid);
  }

  @Test
  public void jwtSignedWithRsaJwk() throws Exception {
    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/rsa-public-key.json");
    JsonWebKey key = JsonMarshaller.fromJson(json, JsonWebKey.class);
    RsaPublicJwk rsaPublicJwk = (RsaPublicJwk) key;
    json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/rsa-private-key.json");
    key = JsonMarshaller.fromJson(json, JsonWebKey.class);
    RsaPrivateJwk rsaPrivateJwk = (RsaPrivateJwk) key;

    JwtClaims claims = new JwtClaims()
      .setAudience("Quality assurance")
      .setIssuer("tester")
      .setIssuedAt(Instant.now())
      .setExpirationTime(Instant.now().plus(5, ChronoUnit.MINUTES))
      .setJwtId(UUID.randomUUID().toString())
      .setSubject("Test")
      .addClaim("email", "foo@bar.com");

    String claimJson = claims.toJson();

    String signedJwtCompact = JwsBuilder.getInstance()
      .withStringPayload(claimJson)
      .sign(rsaPrivateJwk, JwsAlgorithmType.RS256)
      .buildCompact();

    JsonWebSignature jwsDecoded = JsonWebSignature.fromCompactForm(signedJwtCompact);
    assertEquals(1, jwsDecoded.getSignatures().size());

    assertTrue(SignatureValidator.isValid(jwsDecoded.getSignatures().get(0), rsaPublicJwk.getPublicKey()));

    // Verify signature using jose4j
    // Create a new JsonWebSignature object
    org.jose4j.jws.JsonWebSignature jws = new org.jose4j.jws.JsonWebSignature();

    // Set the algorithm constraints based on what is agreed upon or expected from the sender
    jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,
                                                         AlgorithmIdentifiers.RSA_USING_SHA256));

    // Set the compact serialization on the JWS
    jws.setCompactSerialization(signedJwtCompact);

    jws.setKey(rsaPublicJwk.getPublicKey());
    jws.verifySignature();

    assertEquals(claimJson, jws.getPayload());

    // Use JwtConsumerBuilder to construct an appropriate JwtConsumer, which will
    // be used to validate and process the JWT.
    // The specific validation requirements for a JWT are context dependent, however,
    // it typically advisable to require a (reasonable) expiration time, a trusted issuer, and
    // and audience that identifies your system as the intended recipient.
    // If the JWT is encrypted too, you need only provide a decryption key or
    // decryption key resolver to the builder.
    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
      .setRequireExpirationTime() // the JWT must have an expiration time
      .setRequireSubject() // the JWT must have a subject claim
      .setExpectedIssuer("tester") // whom the JWT needs to have been issued by
      .setExpectedAudience("Quality assurance") // to whom the JWT is intended for
      .setVerificationKey(rsaPublicJwk.getPublicKey()) // verify the signature with the public key
      .setJwsAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given context
        new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, // which is only RS256 here
                                 AlgorithmIdentifiers.RSA_USING_SHA256))
      .build();

    org.jose4j.jwt.JwtClaims jwtClaimsDecodedByJose4j = jwtConsumer.processToClaims(signedJwtCompact);
    assertEquals(claims.getJwtId(), jwtClaimsDecodedByJose4j.getJwtId());
  }

  @Test
  public void convertKeyToPem() throws Exception {
    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/rsa-private-key.json");
    JsonWebKey key = JsonMarshaller.fromJson(json, JsonWebKey.class);
    RsaPrivateJwk rsaPrivateJwk = (RsaPrivateJwk) key;

    StringWriter sw = new StringWriter();
    JcaPEMWriter writer = new JcaPEMWriter(sw);
    writer.writeObject(rsaPrivateJwk.getPrivateKey());
    writer.flush();
    System.out.println(sw.toString());
  }
}
