package org.ietf.jose.demo;

import ch.keybridge.lib.jose.JoseFactory;
import org.ietf.jose.jwa.JwsAlgorithmType;
import org.ietf.jose.jwe.JsonWebEncryption;
import org.ietf.jose.jwe.SecretKeyBuilder;
import org.ietf.jose.jws.JsonWebSignature;
import org.ietf.jose.jws.JwsBuilder;
import org.ietf.jose.jws.SignatureValidator;
import org.ietf.jose.jwt.JwtClaims;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 15/05/2018
 */
public class DemoTest {

  @Test
  public void joseSignEncryptPublicPrivateKeys() throws GeneralSecurityException {
    System.out.println("Sign and encrypt using public/private keys\n");
    String sampleText = "sample text to sign and encrypt";

    System.out.println("Original object:");
    System.out.println(sampleText);
    System.out.println();

    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

    KeyPair senderKeyPair = generator.generateKeyPair();
    KeyPair recipientKeyPair = generator.generateKeyPair();

    String json = JoseFactory.SignAndEncrypt.write(sampleText, senderKeyPair.getPrivate(), recipientKeyPair.getPublic(),
        "myKeyId", "receiverPublicKey");
    System.out.println("Signed and encrypted JSON:");
    System.out.println(json);
    System.out.println();

    String decryptedRequest = JoseFactory.SignAndEncrypt.read(json, String.class, recipientKeyPair
                                                       .getPrivate(), senderKeyPair.getPublic());
    Assert.assertEquals(sampleText, decryptedRequest);

    System.out.println("Decrypted object:");
    System.out.println(sampleText);
    System.out.println();
  }

  @Test
  public void WebTokenSignedWithSharedSecretTest() throws Exception {
    final String sharedSecret = "sharedSecret";
    final JwtClaims claims = new JwtClaims()
        .withAudience("audience")
        .withIssuer("tester")
        .withJwtId(UUID.randomUUID().toString())
        .withSubject("some subject")
        .withExpirationTime(ZonedDateTime.now().plus(5, ChronoUnit.MINUTES));
    System.out.println(claims);

    String signedToken = JoseFactory.AuthorizationTokenFactory.createSignedToken(claims, sharedSecret,
        "mySharedSecret");
    System.out.println(signedToken);

    JsonWebSignature jws = JoseFactory.JwsFactory.fromCompactForm(signedToken);
    Assert.assertTrue(SignatureValidator.isValid(jws.getSignature(), sharedSecret));

    JwtClaims decodedClaims = JwtClaims.fromJson(jws.getStringPayload());
    Assert.assertEquals(claims, decodedClaims);
  }

  @Test
  public void WebTokenSignedWithPrivateKeyTest() throws Exception {
    final KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    final JwtClaims claims = new JwtClaims()
        .withAudience("audience")
        .withIssuer("tester")
        .withJwtId(UUID.randomUUID().toString())
        .withSubject("some subject")
        .withExpirationTime(ZonedDateTime.now().plus(5, ChronoUnit.MINUTES));
    System.out.println(claims);

    String signedToken = JoseFactory.AuthorizationTokenFactory.createSignedToken(claims, keyPair.getPrivate(), "myKey");
    System.out.println(signedToken);

    JsonWebSignature jws = JoseFactory.JwsFactory.fromCompactForm(signedToken);
    Assert.assertTrue(SignatureValidator.isValid(jws.getSignature(), keyPair.getPublic()));

    JwtClaims decodedClaims = JwtClaims.fromJson(jws.getStringPayload());
    Assert.assertEquals(claims, decodedClaims);
  }

  @Test
  public void WebTokenEncryptedWithSharedSecretTest() throws Exception {
    final String sharedSecret = "sharedSecret";
    final JwtClaims claims = new JwtClaims()
        .withAudience("audience")
        .withIssuer("tester")
        .withJwtId(UUID.randomUUID().toString())
        .withSubject("some subject")
        .withExpirationTime(ZonedDateTime.now().plus(5, ChronoUnit.MINUTES));
    System.out.println(claims);

    String encryptedToken = JoseFactory.AuthorizationTokenFactory.createEncryptedToken(claims, sharedSecret,
        "mySharedSecret");
    System.out.println(encryptedToken);

    JsonWebEncryption jwe = JoseFactory.Jwefactory.fromCompactForm(encryptedToken);
    String decryptedText = JoseFactory.Jwefactory.decrypt(jwe).decrypt(sharedSecret).getAsString();

    JwtClaims decodedClaims = JwtClaims.fromJson(decryptedText);
    Assert.assertEquals(claims, decodedClaims);
  }

  @Test
  public void WebTokenEncryptedWithPublicKeyTest() throws Exception {
    final KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    final JwtClaims claims = new JwtClaims()
        .withAudience("audience")
        .withIssuer("tester")
        .withJwtId(UUID.randomUUID().toString())
        .withSubject("some subject")
        .withExpirationTime(ZonedDateTime.now().plus(5, ChronoUnit.MINUTES));
    System.out.println(claims);

    String encryptedToken = JoseFactory.AuthorizationTokenFactory.createEncryptedToken(claims, keyPair.getPublic(),
        "mySharedSecret");
    System.out.println(encryptedToken);

    JsonWebEncryption jwe = JoseFactory.Jwefactory.fromCompactForm(encryptedToken);
    String decryptedText = JoseFactory.Jwefactory.decrypt(jwe).decrypt(keyPair.getPrivate()).getAsString();

    JwtClaims decodedClaims = JwtClaims.fromJson(decryptedText);
    Assert.assertEquals(claims, decodedClaims);
  }

  @Test
  public void joseSignEncryptSharedSecret() throws GeneralSecurityException {
    System.out.println("Sign and encrypt using shared keys\n");

    String sampleText = "sample text to sign and encrypt";

    System.out.println("Original object:");
    System.out.println(sampleText);
    System.out.println();

    KeyGenerator generator = KeyGenerator.getInstance("HmacSHA256");
    SecretKey key = SecretKeyBuilder.fromBytes(generator.generateKey().getEncoded());

    String json = JoseFactory.SignAndEncrypt.write(sampleText, key, "myKeyId");
    System.out.println("Signed and encrypted JSON:");
    System.out.println(json);
    System.out.println();

    String decrypted = JoseFactory.SignAndEncrypt.read(json, String.class, key);

    Assert.assertEquals(sampleText, decrypted);

    System.out.println("Decrypted object:");
    System.out.println(sampleText);
    System.out.println();
  }

  @Test
  public void signingWithKeyedHashes() throws GeneralSecurityException, IOException {
    System.out.println("Sign using HMAC\n");

    String sampleText = "sample text to sign";

    JwsAlgorithmType algorithm = JwsAlgorithmType.HS256;

    KeyGenerator generator = KeyGenerator.getInstance(algorithm.getJavaAlgorithmName());
    SecretKey key = generator.generateKey();

    String json = JwsBuilder.getInstance()
      .withStringPayload(sampleText)
        .sign(key, algorithm, UUID.randomUUID().toString())
      .buildJsonWebSignature()
      .toJson();

    System.out.println(json);
    System.out.println();

    /**
     * Signature validation
     */
    JsonWebSignature jws = JsonWebSignature.fromJson(json);
    Assert.assertTrue(SignatureValidator.isValid(jws.getSignatures().get(0), key));
  }

  @Test
  public void signingWithPrivateKeys() throws GeneralSecurityException, IOException {
    System.out.println("Sign using private key\n");

    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

    KeyPair senderKeyPair = generator.generateKeyPair();

    String json = JwsBuilder.getInstance()
      .withStringPayload("sample text to sign")
      .sign(senderKeyPair.getPrivate(), JwsAlgorithmType.RS256, UUID.randomUUID().toString())
      .buildJsonWebSignature()
      .toJson();

    System.out.println(json);
    json = JwsBuilder.getInstance()
      .withStringPayload("sample text to sign")
      .sign(senderKeyPair.getPrivate(), JwsAlgorithmType.RS512, UUID.randomUUID().toString())
      .buildJsonWebSignature()
      .toJson();

    System.out.println(json);
    System.out.println();

    /**
     * Signature validation
     */
    JsonWebSignature jws = JsonWebSignature.fromJson(json);
    Assert.assertTrue(SignatureValidator.isValid(jws.getSignatures().get(0), senderKeyPair.getPublic()));
  }
}
