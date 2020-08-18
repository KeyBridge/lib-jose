package org.ietf.jose.demo;

import ch.keybridge.lib.jose.JoseFactory;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.jwe.JsonWebEncryption;
import org.ietf.jose.jwe.SecretKeyBuilder;
import org.ietf.jose.jws.JsonWebSignature;
import org.ietf.jose.jws.JwsBuilder;
import org.ietf.jose.jws.SignatureValidator;
import org.ietf.jose.jwt.JwtClaims;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 15/05/2018
 * @author Key Bridge
 * @since v0.10.0 rewrite 2020-08-18 to use compound objects since i-json is
 * enabled
 */
public class DemoTest {

  @Test
  public void joseSignEncryptPublicPrivateKeys() throws GeneralSecurityException {

//    System.out.println("Sign and encrypt using public/private keys\n");
    String sampleText = "sample text to sign and encrypt";

    DemoDto dto = new DemoDto(sampleText);

//    System.out.println("Original object:");
//    System.out.println(sampleText);
//    System.out.println();
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

    KeyPair senderKeyPair = generator.generateKeyPair();
    KeyPair recipientKeyPair = generator.generateKeyPair();
    /**
     * Write `sampleText` as a signed and encrypted JSON string.
     */
    String signEncryptJson = JoseFactory.SignAndEncrypt.write(dto,
                                                              senderKeyPair.getPrivate(),
                                                              recipientKeyPair.getPublic(),
                                                              "myKeyId",
                                                              "receiverPublicKey");
//    System.out.println("Signed and encrypted JSON:");
//    System.out.println(signEncryptJson);
//    System.out.println();

    DemoDto decryptedDto = JoseFactory.SignAndEncrypt.read(signEncryptJson,
                                                           DemoDto.class,
                                                           recipientKeyPair.getPrivate(),
                                                           senderKeyPair.getPublic());
    Assert.assertEquals(dto, decryptedDto);

//    System.out.println("Decrypted object:");
//    System.out.println(sampleText);
//    System.out.println();
    System.out.println("joseSignEncryptPublicPrivateKeys OK");
  }

  @Test
  public void joseWebTokenSignedWithSharedSecretTest() throws Exception {
    final String sharedSecret = "sharedSecret";
    final JwtClaims claims = new JwtClaims()
      .withAudience("audience")
      .withIssuer("tester")
      .withJwtId(UUID.randomUUID().toString())
      .withSubject("some subject")
      .withExpirationTime(ZonedDateTime.now().plus(5, ChronoUnit.MINUTES));
//    System.out.println(claims);

    String signedToken = JoseFactory.AuthorizationTokenFactory.createSignedToken(claims,
                                                                                 sharedSecret,
                                                                                 "mySharedSecret");
//    System.out.println(signedToken);

    JsonWebSignature jws = JoseFactory.JwsFactory.fromCompactForm(signedToken);
//    System.out.println("key ID: " + jws.getSignature().getProtectedHeader().getKid());
    Assert.assertTrue(SignatureValidator.isValid(jws.getSignature(), sharedSecret));

    JwtClaims decodedClaims = JwtClaims.fromJson(jws.getStringPayload());
    Assert.assertEquals(claims, decodedClaims);
    System.out.println("joseWebTokenSignedWithSharedSecretTest OK");
  }

  @Test
  public void joseWebTokenSignedWithPrivateKeyTest() throws Exception {
    final KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    final JwtClaims claims = new JwtClaims()
      .withAudience("audience")
      .withIssuer("tester")
      .withJwtId(UUID.randomUUID().toString())
      .withSubject("some subject")
      .withExpirationTime(ZonedDateTime.now().plus(5, ChronoUnit.MINUTES));
//    System.out.println(claims);

    String signedToken = JoseFactory.AuthorizationTokenFactory.createSignedToken(claims,
                                                                                 keyPair.getPrivate(),
                                                                                 "myKey");
//    System.out.println(signedToken);

    JsonWebSignature jws = JoseFactory.JwsFactory.fromCompactForm(signedToken);
    Assert.assertTrue(SignatureValidator.isValid(jws.getSignature(), keyPair.getPublic()));

    JwtClaims decodedClaims = JwtClaims.fromJson(jws.getStringPayload());
    Assert.assertEquals(claims, decodedClaims);
    System.out.println("joseWebTokenSignedWithPrivateKeyTest OK");
  }

  @Test
  public void joseWebTokenEncryptedWithSharedSecretTest() throws Exception {
    final String sharedSecret = "sharedSecret";
    final JwtClaims claims = new JwtClaims()
      .withAudience("audience")
      .withIssuer("tester")
      .withJwtId(UUID.randomUUID().toString())
      .withSubject("some subject")
      .withExpirationTime(ZonedDateTime.now().plus(5, ChronoUnit.MINUTES));
//    System.out.println(claims);

    String encryptedToken = JoseFactory.AuthorizationTokenFactory.createEncryptedToken(claims,
                                                                                       sharedSecret,
                                                                                       "mySharedSecret");
//    System.out.println(encryptedToken);

    JsonWebEncryption jwe = JoseFactory.Jwefactory.fromCompactForm(encryptedToken);
    String decryptedText = JoseFactory.Jwefactory.decrypt(jwe).decrypt(sharedSecret).getAsString();

    JwtClaims decodedClaims = JwtClaims.fromJson(decryptedText);

//    System.out.println("  originalClaims " + claims.toJson());
//    System.out.println("  decodedClaims  " + decodedClaims.toJson());
    Assert.assertEquals(claims, decodedClaims);
    System.out.println("joseWebTokenEncryptedWithSharedSecretTest OK");
  }

  @Test
  public void joseWebTokenEncryptedWithPublicKeyTest() throws Exception {
    final KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    final JwtClaims claims = new JwtClaims()
      .withAudience("audience")
      .withIssuer("tester")
      .withJwtId(UUID.randomUUID().toString())
      .withSubject("some subject")
      .withExpirationTime(ZonedDateTime.now().plus(5, ChronoUnit.MINUTES));
//    System.out.println(claims);

    String encryptedToken = JoseFactory.AuthorizationTokenFactory.createEncryptedToken(claims,
                                                                                       keyPair.getPublic(),
                                                                                       "mySharedSecret");
//    System.out.println(encryptedToken);

    JsonWebEncryption jwe = JoseFactory.Jwefactory.fromCompactForm(encryptedToken);
    String decryptedText = JoseFactory.Jwefactory.decrypt(jwe).decrypt(keyPair.getPrivate()).getAsString();

    JwtClaims decodedClaims = JwtClaims.fromJson(decryptedText);
    Assert.assertEquals(claims, decodedClaims);
    System.out.println("joseWebTokenEncryptedWithPublicKeyTest OK");
  }

  @Test
  public void joseSignEncryptSharedSecret() throws GeneralSecurityException {
//    System.out.println("Sign and encrypt using shared keys\n");
    String sampleText = "sample text to sign and encrypt";
    DemoDto dto = new DemoDto(sampleText);

    KeyGenerator generator = KeyGenerator.getInstance("HmacSHA256");
    SecretKey key = SecretKeyBuilder.fromBytes(generator.generateKey().getEncoded());

    String json = JoseFactory.SignAndEncrypt.write(dto, key, "myKeyId");
//    System.out.println("  Original                   : " + dto);
//    System.out.println("  Signed and encrypted JSON  : " + json);

    DemoDto decryptedDto = JoseFactory.SignAndEncrypt.read(json, DemoDto.class, key);

    Assert.assertEquals(dto, decryptedDto);

//    System.out.println("  Decrypted object           : " + decryptedDto);
//    System.out.println("joseSignEncryptSharedSecret OK");
  }

  @Test
  public void joseSigningWithKeyedHashes() throws GeneralSecurityException, IOException {
//    System.out.println("Sign using HMAC\n");

    String sampleText = "sample text to sign";

    JwsAlgorithmType algorithm = JwsAlgorithmType.HS256;

    KeyGenerator generator = KeyGenerator.getInstance(algorithm.getJavaAlgorithmName());
    SecretKey key = generator.generateKey();

    String json = JwsBuilder.getInstance()
      .withStringPayload(sampleText)
      .sign(key, algorithm, UUID.randomUUID().toString())
      .buildJsonWebSignature()
      .toJson();

//    System.out.println(json);
//    System.out.println();
    /**
     * Signature validation
     */
    JsonWebSignature jws = JsonWebSignature.fromJson(json);
    Assert.assertTrue(SignatureValidator.isValid(jws.getSignatures().get(0), key));

    System.out.println("joseSigningWithKeyedHashes OK");
  }

  @Test
  public void joseSigningWithPrivateKeys() throws GeneralSecurityException, IOException {
//    System.out.println("Sign using private key\n");

    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

    KeyPair senderKeyPair = generator.generateKeyPair();

    String json = JwsBuilder.getInstance()
      .withStringPayload("sample text to sign")
      .sign(senderKeyPair.getPrivate(), JwsAlgorithmType.RS256, UUID.randomUUID().toString())
      .buildJsonWebSignature()
      .toJson();

//    System.out.println(json);
    json = JwsBuilder.getInstance()
      .withStringPayload("sample text to sign")
      .sign(senderKeyPair.getPrivate(), JwsAlgorithmType.RS512, UUID.randomUUID().toString())
      .buildJsonWebSignature()
      .toJson();

//    System.out.println(json);
//    System.out.println();
    /**
     * Signature validation
     */
    JsonWebSignature jws = JsonWebSignature.fromJson(json);
    Assert.assertTrue(SignatureValidator.isValid(jws.getSignatures().get(0), senderKeyPair.getPublic()));

    System.out.println("joseSigningWithPrivateKeys OK");
  }
}
