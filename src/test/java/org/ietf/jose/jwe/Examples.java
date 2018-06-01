package org.ietf.jose.jwe;

import org.ietf.jose.jwk.key.RsaPrivateJwk;
import org.ietf.jose.jwk.key.RsaPublicJwk;
import org.ietf.jose.util.JsonMarshaller;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import static org.junit.Assert.assertEquals;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 29/05/2018
 */
public class Examples {

  private KeyPair keyPair;
  private String keyId = UUID.randomUUID().toString();

  @Before
  public void generateKeyPair() throws NoSuchAlgorithmException {
    keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
  }

  @Test
  public void printKeysAsJwk() throws IOException {
    RsaPrivateJwk jwkPrivateKey = RsaPrivateJwk.getInstance(keyPair, keyId);
    System.out.println("Private key:");
    System.out.println(JsonMarshaller.toJson(jwkPrivateKey));
    System.out.println();

    RsaPublicJwk jwkPublicKey = RsaPublicJwk.getInstance((RSAPublicKey) keyPair.getPublic());
    System.out.println("Public key:");
    System.out.println(JsonMarshaller.toJson(jwkPublicKey));
    System.out.println();
  }

  @Test
  public void createConsumeAndValidateExample() throws Exception {

    /**
     * Create a JSON Web Encryption object with a string as payload
     */
    JweJsonFlattened jwe = JweBuilder.getInstance()
        .withStringPayload("hi")
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
    JweJsonFlattened fromCompact = JweJsonFlattened.fromCompactForm(jweCompact);
    // From JSON Flattened form
    JweJsonFlattened fromJson = JweJsonFlattened.fromJson(jwe.toJson());

    assertEquals(jwe, fromCompact);
    assertEquals(jwe, fromJson);

    /**
     * Validate the JWT
     *
     * A JWE object is implicitly validated during decryption. Unsuccessful decryption means
     * that either an incorrect decryption key has been used or that the encrypted message has been
     * tampered with and is invalid.
     */
  }
}
