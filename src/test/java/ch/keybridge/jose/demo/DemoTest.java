package ch.keybridge.jose.demo;

import ch.keybridge.jose.JOSE;
import ch.keybridge.jose.jws.SignatureAlgorithmType;
import ch.keybridge.jose.jws.JwsBuilder;
import ch.keybridge.jose.jws.JwsJsonFlattened;
import ch.keybridge.jose.util.Base64Utility;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.junit.Assert;
import org.junit.Test;

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

    String json = JOSE.write(sampleText, senderKeyPair.getPrivate(), recipientKeyPair.getPublic(), "myKeyId");
    System.out.println("Signed and encrypted JSON:");
    System.out.println(json);
    System.out.println();

    String decryptedRequest = JOSE.read(json, String.class, recipientKeyPair
                                        .getPrivate(), senderKeyPair.getPublic());
    Assert.assertEquals(sampleText, decryptedRequest);

    System.out.println("Decrypted object:");
    System.out.println(sampleText);
    System.out.println();
  }

  @Test
  public void joseSignEncryptSharedSecret() throws GeneralSecurityException {
    System.out.println("Sign and encrypt using shared keys\n");

    String sampleText = "sample text to sign and encrypt";

    System.out.println("Original object:");
    System.out.println(sampleText);
    System.out.println();

    KeyGenerator generator = KeyGenerator.getInstance("HmacSHA256");
    SecretKey key = generator.generateKey();

    String base64UrlEncodedSecret = Base64Utility.toBase64Url(key.getEncoded());

    String json = JOSE.write(sampleText, base64UrlEncodedSecret, "myKeyId"); // java.security.InvalidKeyException: Illegal key size
    System.out.println("Signed and encrypted JSON:");
    System.out.println(json);
    System.out.println();

    String decrypted = JOSE.read(json, String.class, base64UrlEncodedSecret);

    Assert.assertEquals(sampleText, decrypted);

    System.out.println("Decrypted object:");
    System.out.println(sampleText);
    System.out.println();
  }

  @Test
  public void signingWithKeyedHashes() throws GeneralSecurityException, IOException {
    System.out.println("Sign using HMAC\n");

    String sampleText = "sample text to sign";

    KeyGenerator generator = KeyGenerator.getInstance("HmacSHA256");
    SecretKey key = generator.generateKey();

    String base64UrlEncodedSecret = Base64Utility.toBase64Url(key.getEncoded());

    String json = JwsBuilder.getInstance()
      .withStringPayload(sampleText)
      .sign(base64UrlEncodedSecret)
      .buildJsonFlattened()
      .toJson();

    System.out.println(json);
    System.out.println();

    /**
     * Signature validation
     */
    JwsJsonFlattened jws = JwsJsonFlattened.fromJson(json);
    Assert.assertTrue(jws.getJwsSignature().isValidSignature(jws.getPayload(), base64UrlEncodedSecret));
  }

  @Test
  public void signingWithPrivateKeys() throws GeneralSecurityException, IOException {
    System.out.println("Sign using private key\n");

    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

    KeyPair senderKeyPair = generator.generateKeyPair();

    String json = JwsBuilder.getInstance()
      .withStringPayload("sample text to sign")
      .sign(senderKeyPair.getPrivate(), SignatureAlgorithmType.RS256)
      .buildJsonFlattened()
      .toJson();

    System.out.println(json);
    json = JwsBuilder.getInstance()
      .withStringPayload("sample text to sign")
      .sign(senderKeyPair.getPrivate(), SignatureAlgorithmType.RS512)
      .buildJsonFlattened()
      .toJson();

    System.out.println(json);
    System.out.println();

    /**
     * Signature validation
     */
    JwsJsonFlattened jws = JwsJsonFlattened.fromJson(json);
    Assert.assertTrue(jws.getJwsSignature().isValidSignature(jws.getPayload(), senderKeyPair.getPublic()));
  }
}
