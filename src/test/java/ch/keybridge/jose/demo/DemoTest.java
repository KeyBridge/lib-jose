package ch.keybridge.jose.demo;

import ch.keybridge.jose.JOSE;
import ch.keybridge.jose.jws.ESignatureAlgorithm;
import ch.keybridge.jose.jws.JwsBuilder;
import ch.keybridge.jose.jws.JwsJsonFlattened;
import ch.keybridge.jose.util.Base64Utility;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 15/05/2018
 */
public class DemoTest {
  @Test
  public void joseSignEncryptPublicPrivateKeys() throws GeneralSecurityException {
    SasRegistrationRequest registrationRequest = new SasRegistrationRequest();
    registrationRequest.setHardwareAddress("someHardwareAddress");
    registrationRequest.setUrl("http://localhost:8080");
    registrationRequest.setInet4Address("127.0.0.1");

    System.out.println("Original object:");
    System.out.println(registrationRequest);
    System.out.println();

    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

    KeyPair senderKeyPair = generator.generateKeyPair();
    KeyPair recipientKeyPair = generator.generateKeyPair();

    String json = JOSE.write(registrationRequest, senderKeyPair.getPrivate(), recipientKeyPair.getPublic(), "senderId");
    System.out.println("Signed and encrypted JSON:");
    System.out.println(json);
    System.out.println();

    SasRegistrationRequest decryptedRequest = JOSE.read(json, SasRegistrationRequest.class, recipientKeyPair
        .getPrivate(), senderKeyPair.getPublic());
    Assert.assertEquals(registrationRequest, decryptedRequest);

    System.out.println("Decrypted object:");
    System.out.println(registrationRequest);
  }

  @Test
  public void joseSignEncryptSharedSecret() throws GeneralSecurityException {
    EscNotificationMessage message = new EscNotificationMessage();
    message.setActive(true);
    message.setChannelName("CBRS5");
    message.setDpaId("DPA002");

    System.out.println("Original object:");
    System.out.println(message);
    System.out.println();

    KeyGenerator generator = KeyGenerator.getInstance("HmacSHA256");
    SecretKey key = generator.generateKey();

    String base64UrlEncodedSecret = Base64Utility.toBase64Url(key.getEncoded());

    String json = JOSE.write(message, base64UrlEncodedSecret, "senderId");
    System.out.println("Signed and encrypted JSON:");
    System.out.println(json);
    System.out.println();

    EscNotificationMessage decrypted = JOSE.read(json, EscNotificationMessage.class, base64UrlEncodedSecret);

    Assert.assertEquals(message, decrypted);

    System.out.println("Decrypted object:");
    System.out.println(message);
  }

  @Test
  public void signingWithKeyedHashes() throws GeneralSecurityException, IOException {
    KeyGenerator generator = KeyGenerator.getInstance("HmacSHA256");
    SecretKey key = generator.generateKey();

    String base64UrlEncodedSecret = Base64Utility.toBase64Url(key.getEncoded());

    String json = JwsBuilder.getInstance()
        .withStringPayload("Some payload")
        .sign(base64UrlEncodedSecret)
        .buildJsonFlattened()
        .toJson();

    System.out.println(json);

    /**
     * Signature validation
     */
    JwsJsonFlattened jws = JwsJsonFlattened.fromJson(json);
    Assert.assertTrue(jws.getJwsSignature().isValidSignature(jws.getPayload(), base64UrlEncodedSecret));
  }

  @Test
  public void signingWithPrivateKeys() throws GeneralSecurityException, IOException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

    KeyPair senderKeyPair = generator.generateKeyPair();

    String json = JwsBuilder.getInstance()
        .withStringPayload("Some payload")
        .sign(senderKeyPair.getPrivate(), ESignatureAlgorithm.RS256)
        .buildJsonFlattened()
        .toJson();

    System.out.println(json);
    json = JwsBuilder.getInstance()
        .withStringPayload("Some payload")
        .sign(senderKeyPair.getPrivate(), ESignatureAlgorithm.RS512)
        .buildJsonFlattened()
        .toJson();

    System.out.println(json);

    /**
     * Signature validation
     */
    JwsJsonFlattened jws = JwsJsonFlattened.fromJson(json);
    Assert.assertTrue(jws.getJwsSignature().isValidSignature(jws.getPayload(), senderKeyPair.getPublic()));
  }
}
