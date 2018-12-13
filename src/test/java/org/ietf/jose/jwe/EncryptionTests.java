package org.ietf.jose.jwe;

import org.ietf.jose.util.JsonMarshaller;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

import static org.junit.Assert.assertEquals;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 29/05/2018
 */
public class EncryptionTests {

  private KeyPair keyPair;
  private String keyId = UUID.randomUUID().toString();

  @Before
  public void generateKeyPair() throws NoSuchAlgorithmException {
    keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
  }

  @Test
  public void internationalStringTest() throws Exception {
    /**
     * Take a valid but non-English string, encrypt and decrypt it, and check it's identical
     */
    String plaintext = "ąęč„ė“čūį“įęūš“-";
    JsonWebEncryption jwe = JweBuilder.getInstance()
        .withStringPayload(plaintext)
        // sign it with our private key and specify a random UUID as the key ID
        .buildJweJsonFlattened(keyPair.getPublic());
    String jweCompact = jwe.toCompactForm();

    System.out.println("JWE JSON flattened:\n" + JsonMarshaller.toJsonPrettyFormatted(jwe));
    System.out.println();
    System.out.println("JWE compact form:\n" + jweCompact);
    System.out.println();

    /**
     * Consume the JWE
     */
    // From compact form
    JsonWebEncryption fromCompact = JsonWebEncryption.fromCompactForm(jweCompact);
    // From JSON Flattened form
    JsonWebEncryption fromJson = JsonWebEncryption.fromJson(jwe.toJson());

    assertEquals(jwe, fromCompact);
    assertEquals(jwe, fromJson);

    String decryptedPlaintext = JweDecryptor.createFor(fromJson)
        .decrypt(keyPair.getPrivate())
        .getAsString();
    System.out.println("plaintext: " + decryptedPlaintext);
    Assert.assertEquals(plaintext, decryptedPlaintext);
  }
}
