package org.ietf.jose.jwe;

import org.ietf.TestFileReader;
import org.ietf.TestUtil;
import org.ietf.jose.jwa.JweEncryptionAlgorithmType;
import org.ietf.jose.jwa.JweKeyAlgorithmType;
import org.ietf.jose.jwe.encryption.AesGcmEncrypter;
import org.ietf.jose.jwe.encryption.DefaultEncrypter;
import org.ietf.jose.jwe.encryption.Encrypter;
import org.ietf.jose.jwe.encryption.EncryptionResult;
import org.ietf.jose.jwk.key.RsaPrivateJwk;
import org.ietf.jose.jwk.key.SymmetricJwk;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static junit.framework.TestCase.fail;
import static org.ietf.jose.util.Base64Utility.toBase64Url;
import static org.ietf.jose.util.JsonMarshaller.fromJson;
import static org.ietf.jose.util.JsonMarshaller.toJson;
import static org.junit.Assert.*;

public class JWETest {

  private static byte[] concatenate(byte[] aad, byte[] iv, byte[] ciphertext, byte[] a) {
    byte[] output = new byte[aad.length + iv.length + ciphertext.length + a.length];
    int idx = 0;
    System.arraycopy(aad, 0, output, idx, aad.length);
    idx += aad.length;
    System.arraycopy(iv, 0, output, idx, iv.length);
    idx += iv.length;
    System.arraycopy(ciphertext, 0, output, idx, ciphertext.length);
    idx += ciphertext.length;
    System.arraycopy(a, 0, output, idx, a.length);
    return output;
  }

  @Test
  public void encryptDecryptRsa2048Test() throws Exception {
    String payloadString = "some text to test with";
    byte[] payload = payloadString.getBytes(UTF_8);

    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair pair = generator.generateKeyPair();

    JweJsonFlattened jwe = JweBuilder.getInstance()
      .withBinaryPayload(payload)
      .buildJweJsonFlattened(pair.getPublic());

    String compactForm = jwe.toCompactForm();

    JweJsonFlattened fromCompact = JweJsonFlattened.fromCompactForm(compactForm);

    assertEquals(jwe, fromCompact);

    byte[] decrypted = JweDecryptor.createFor(jwe)
        .decrypt(pair.getPrivate())
        .getAsBytes();

    assertArrayEquals(payload, decrypted);
  }

  @Test
  public void encryptDecryptRsa1024Test() throws Exception {
    String payloadString = "some text to test with";
    byte[] payload = payloadString.getBytes(UTF_8);

    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(1024);
    KeyPair pair = generator.generateKeyPair();

    JweJsonFlattened jwe = JweBuilder.getInstance()
      .withBinaryPayload(payload)
      .buildJweJsonFlattened(pair.getPublic());

    byte[] decrypted = JweDecryptor.createFor(jwe)
        .decrypt(pair.getPrivate())
        .getAsBytes();

    assertArrayEquals(payload, decrypted);
  }

  @Test
  public void encryptDecryptStringTest() throws Exception {
    String stringPayload = "some text to test with";
    byte[] binaryPayload = stringPayload.getBytes(StandardCharsets.UTF_8);

    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(1024);
    KeyPair pair = generator.generateKeyPair();

    JweJsonFlattened jwe = JweBuilder.getInstance()
        .withStringPayload(stringPayload)
      .buildJweJsonFlattened(pair.getPublic());

    String decrypted = JweDecryptor.createFor(jwe)
        .decrypt(pair.getPrivate())
        .getAsString();

    assertEquals(stringPayload, decrypted);

    jwe = JweBuilder.getInstance()
        .withStringPayload(stringPayload)
        .buildJweJsonFlattened(pair.getPublic());

    byte[] decryptedBytes = JweDecryptor.createFor(jwe)
        .decrypt(pair.getPrivate())
        .getAsBytes();

    assertArrayEquals(binaryPayload, decryptedBytes);
  }

  @Test
  public void appendixA1Test() throws Exception {
    /**
     * Appendix A. JWE Examples
     * <p>
     * This section provides examples of JWE computations.
     * <p>
     * A.1. Example JWE using RSAES-OAEP and AES GCM
     * <p>
     * This example encrypts the plaintext "The true sign of intelligence is not
     * knowledge but imagination." to the recipient using RSAES-OAEP for key
     * encryption and AES GCM for content encryption. The representation of this
     * plaintext (using JSON array notation) is: [84, 104, 101, 32, 116, 114,
     * 117, 101, 32, 115, 105, 103, 110, 32, 111, 102, 32, 105, 110, 116, 101,
     * 108, 108, 105, 103, 101, 110, 99, 101, 32, 105, 115, 32, 110, 111, 116,
     * 32, 107, 110, 111, 119, 108, 101, 100, 103, 101, 32, 98, 117, 116, 32,
     * 105, 109, 97, 103, 105, 110, 97, 116, 105, 111, 110, 46]
     */
    final String plaintext = "The true sign of intelligence is not knowledge but imagination.";
    assertArrayEquals(new byte[]{84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32,
                                 111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99,
                                 101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119, 108,
                                 101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105,
                                 110, 97, 116, 105, 111, 110, 46}, plaintext.getBytes(UTF_8));
    /**
     * A.1.1. JOSE Header The following example JWE Protected Header declares
     * that: o The Content Encryption Key is encrypted to the recipient using
     * the RSAES-OAEP algorithm to produce the JWE Encrypted Key. o
     * Authenticated encryption is performed on the plaintext using the AES GCM
     * algorithm with a 256-bit key to produce the ciphertext and the
     * Authentication Tag. {"alg":"RSA-OAEP","enc":"A256GCM"}
     */
    JweHeader joseHeader = new JweHeader();
    joseHeader.setAlg("RSA-OAEP");
    joseHeader.setEnc(JweEncryptionAlgorithmType.A256GCM);

    String joseHeaderJson = toJson(joseHeader);
//    System.out.println(joseHeaderJson);
    /**
     * Encoding this JWE Protected Header as BASE64URL(UTF8(JWE Protected
     * Header)) gives this value: eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ
     */
    assertEquals("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ", toBase64Url(joseHeaderJson));

    /**
     * A.1.2. Content Encryption Key (CEK) Generate a 256-bit random CEK. In
     * this example, the value (using JSON array notation) is: [177, 161, 244,
     * 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7, 110,
     * 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252]
     */
    final int[] cek = new int[]{
      177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
      212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
      234, 64, 252
    };
    final byte[] cekBytes = TestUtil.convertUnsignedIntsToBytes(cek);
    assertArrayEquals(cek, TestUtil.toUnsignedInt(cekBytes)); // sanity check
    /**
     * A.1.3. Key Encryption
     * <p>
     * Encrypt the CEK with the recipient’s public key using the RSAES-OAEP
     * algorithm to produce the JWE Encrypted Key. This example uses the RSA key
     * represented in JSON Web Key [JWK] format below (with line breaks within
     * values for display purposes only):
     */
    final String jwkJson = TestFileReader.getTestCase("/rfc7516/appendix-a/rsa-private-key.json");

    RsaPrivateJwk key = fromJson(jwkJson, RsaPrivateJwk.class);
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key.getPublicKey());
    byte[] encryptedKey = cipher.doFinal(cekBytes);

    cipher.init(Cipher.DECRYPT_MODE, key.getPrivateKey());
    byte[] decryptedKey = cipher.doFinal(encryptedKey);

    assertArrayEquals(decryptedKey, cekBytes);

    /**
     * The resulting JWE Encrypted Key value is:
     */
    int[] encExpected = new int[]{
      56, 163, 154, 192, 58, 53, 222, 4, 105, 218, 136, 218, 29, 94, 203,
      22, 150, 92, 129, 94, 211, 232, 53, 89, 41, 60, 138, 56, 196, 216,
      82, 98, 168, 76, 37, 73, 70, 7, 36, 8, 191, 100, 136, 196, 244, 220,
      145, 158, 138, 155, 4, 117, 141, 230, 199, 247, 173, 45, 182, 214,
      74, 177, 107, 211, 153, 11, 205, 196, 171, 226, 162, 128, 171, 182,
      13, 237, 239, 99, 193, 4, 91, 219, 121, 223, 107, 167, 61, 119, 228,
      173, 156, 137, 134, 200, 80, 219, 74, 253, 56, 185, 91, 177, 34, 158,
      89, 154, 205, 96, 55, 18, 138, 43, 96, 218, 215, 128, 124, 75, 138,
      243, 85, 25, 109, 117, 140, 26, 155, 249, 67, 167, 149, 231, 100, 6,
      41, 65, 214, 251, 232, 87, 72, 40, 182, 149, 154, 168, 31, 193, 126,
      215, 89, 28, 111, 219, 125, 182, 139, 235, 195, 197, 23, 234, 55, 58,
      63, 180, 68, 202, 206, 149, 75, 205, 248, 176, 67, 39, 178, 60, 98,
      193, 32, 238, 122, 96, 158, 222, 57, 183, 111, 210, 55, 188, 215,
      206, 180, 166, 150, 166, 106, 250, 55, 229, 72, 40, 69, 214, 216,
      104, 23, 40, 135, 212, 28, 127, 41, 80, 175, 174, 168, 115, 171, 197,
      89, 116, 92, 103, 246, 83, 216, 182, 176, 84, 37, 147, 35, 45, 219,
      172, 99, 226, 233, 73, 37, 124, 42, 72, 49, 242, 35, 127, 184, 134,
      117, 114, 135, 206
    };
    /**
     * A.1.8. Validation
     * <p>
     * This example illustrates the process of creating a JWE with RSAES-OAEP
     * for key encryption and AES GCM for content encryption. These results can
     * be used to validate JWE decryption implementations for these algorithms.
     * Note that since the RSAES-OAEP computation includes random values, the
     * encryption results above will not be completely reproducible. However,
     * since the AES GCM computation is deterministic, the JWE Encrypted
     * Ciphertext values will be the same for all encryptions performed using
     * these inputs.
     * <p>
     * Developer note: RSAES-OAEP encryption result lengths are expected to
     * match but not the contents
     */
    assertEquals(encExpected.length, encryptedKey.length);

    /**
     *
     * A.1.4. Initialization Vector Generate a random 96-bit JWE Initialization
     * Vector. In this example, the value is: [227, 197, 117, 252, 2, 219, 233,
     * 68, 180, 225, 77, 219] Encoding this JWE Initialization Vector as
     * BASE64URL(JWE Initialization Vector) gives this value: 48V1_ALb6US04U3b
     */
    final byte[] initVector = TestUtil.convertUnsignedIntsToBytes(new int[]{227, 197, 117, 252, 2, 219, 233, 68, 180,
                                                                            225, 77, 219});
    final String initVectorBase64 = toBase64Url(initVector);
    assertEquals("48V1_ALb6US04U3b", initVectorBase64);

    /**
     * A.1.5. Additional Authenticated Data Let the Additional Authenticated
     * Data encryption parameter be ASCII(BASE64URL(UTF8(JWE Protected
     * Header))). This value is: [101, 121, 74, 104, 98, 71, 99, 105, 79, 105,
     * 74, 83, 85, 48, 69, 116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86,
     * 117, 89, 121, 73, 54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105,
     * 102, 81]
     */
    final byte[] aad = TestUtil.convertUnsignedIntsToBytes(new int[]{101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74,
                                                                     83, 85, 48, 69, 116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73, 54, 73, 107, 69, 121, 78,
                                                                     84, 90, 72, 81, 48, 48, 105, 102, 81});

    /**
     * A.1.6. Content Encryption Perform authenticated encryption on the
     * plaintext with the AES GCM algorithm using the CEK as the encryption key,
     * the JWE Initialization Vector, and the Additional Authenticated Data
     * value above, requesting a 128-bit Authentication Tag output.
     */
    GCMParameterSpec myParams = new GCMParameterSpec(128, initVector);
    Cipher cipher1 = Cipher.getInstance("AES/GCM/NoPadding");
    /**
     * Developer note: Additional files may need to be downloaded and copied
     * into the Java installation security directory
     * https://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters
     */
    Key aesKey = new SecretKeySpec(cekBytes, "AES");
    cipher1.init(Cipher.ENCRYPT_MODE, aesKey, myParams);
    cipher1.updateAAD(aad);
    int cypherLen = plaintext.getBytes(UTF_8).length;
    byte[] cypherAndAuthTag = cipher1.doFinal(plaintext.getBytes(UTF_8));
    byte[] cypher = Arrays.copyOf(cypherAndAuthTag, cypherLen);
    byte[] authTag = Arrays.copyOfRange(cypherAndAuthTag, cypherLen, cypherAndAuthTag.length);
    assertArrayEquals(new int[]{229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122,
                                233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219, 186, 80, 111,
                                104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40, 82, 242, 32,
                                123, 143, 168, 226, 73, 216, 176, 144, 138, 247, 106, 60, 16, 205,
                                160, 109, 64, 63, 192}, TestUtil.toUnsignedInt(cypher));
    assertArrayEquals(new int[]{92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91,
                                210, 145}, TestUtil.toUnsignedInt(authTag));
  }

  @Test
  public void appendixA2Test() throws Exception {
    /**
     * A.2. Example JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256 This
     * example encrypts the plaintext "Live long and prosper." to the recipient
     * using RSAES-PKCS1-v1_5 for key encryption and AES_128_CBC_HMAC_SHA_256
     * for content encryption. The representation of this plaintext (using JSON
     * array notation) is:
     * <p>
     */
    final String plaintext = "Live long and prosper.";
    assertArrayEquals(new byte[]{76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
                                 112, 114, 111, 115, 112, 101, 114, 46}, plaintext.getBytes(UTF_8));
    /**
     * A.2.1. JOSE Header The following example JWE Protected Header declares
     * that:
     * <p>
     * o The Content Encryption Key is encrypted to the recipient using the
     * RSAES-PKCS1-v1_5 algorithm to produce the JWE Encrypted Key. o
     * Authenticated encryption is performed on the plaintext using the
     * AES_128_CBC_HMAC_SHA_256 algorithm to produce the ciphertext and the
     * Authentication Tag.
     * <p>
     * {"alg":"RSA1_5","enc":"A128CBC-HS256"}
     */
    final JweKeyAlgorithmType keyManagementAlgorithm = JweKeyAlgorithmType.RSA1_5;
    final JweEncryptionAlgorithmType contentEncyptionAlgorithm = JweEncryptionAlgorithmType.A128CBC_HS256;
    JweHeader joseHeader = new JweHeader();
    joseHeader.setAlg(keyManagementAlgorithm.getJoseAlgorithmName());
    joseHeader.setEnc(contentEncyptionAlgorithm);

    String joseHeaderJson = toJson(joseHeader);
//    System.out.println(joseHeaderJson);
    /**
     * Encoding this JWE Protected Header as BASE64URL(UTF8(JWE Protected
     * Header)) gives this value:
     * eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0
     */
    assertEquals("eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0", toBase64Url(joseHeaderJson));

    /**
     * A.1.2. Content Encryption Key (CEK) Generate a 256-bit random CEK. In
     * this example, the value (using JSON array notation) is: [177, 161, 244,
     * 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7, 110,
     * 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252]
     */
    final int[] cek = new int[]{
      4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
      206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
      44, 207
    };
    final byte[] cekBytes = TestUtil.convertUnsignedIntsToBytes(cek);
    assertArrayEquals(cek, TestUtil.toUnsignedInt(cekBytes)); // sanity check
    /**
     * A.2.3. Key Encryption Encrypt the CEK with the recipient’s public key
     * using the RSAES-PKCS1-v1_5 algorithm to produce the JWE Encrypted Key.
     * This example uses the RSA key represented in JSON Web Key [JWK] format
     * below (with line breaks within values for display purposes only):
     */
    final String jwkJson = TestFileReader.getTestCase("/rfc7516/appendix-a/rsa-private-key-appendix-a2.json");

    RsaPrivateJwk key = fromJson(jwkJson, RsaPrivateJwk.class);

    Cipher cipher = Cipher.getInstance(keyManagementAlgorithm.getJavaAlgorithm());
    cipher.init(Cipher.ENCRYPT_MODE, key.getPublicKey());
    byte[] enc = cipher.doFinal(cekBytes);

    Cipher cipher2 = Cipher.getInstance(keyManagementAlgorithm.getJavaAlgorithm());
    cipher2.init(Cipher.DECRYPT_MODE, key.getPrivateKey());
    byte[] enc2 = cipher2.doFinal(enc);

    assertArrayEquals(enc2, cekBytes);

    int[] encExpected = new int[]{
      80, 104, 72, 58, 11, 130, 236, 139, 132, 189, 255, 205, 61, 86, 151,
      176, 99, 40, 44, 233, 176, 189, 205, 70, 202, 169, 72, 40, 226, 181,
      156, 223, 120, 156, 115, 232, 150, 209, 145, 133, 104, 112, 237, 156,
      116, 250, 65, 102, 212, 210, 103, 240, 177, 61, 93, 40, 71, 231, 223,
      226, 240, 157, 15, 31, 150, 89, 200, 215, 198, 203, 108, 70, 117, 66,
      212, 238, 193, 205, 23, 161, 169, 218, 243, 203, 128, 214, 127, 253,
      215, 139, 43, 17, 135, 103, 179, 220, 28, 2, 212, 206, 131, 158, 128,
      66, 62, 240, 78, 186, 141, 125, 132, 227, 60, 137, 43, 31, 152, 199,
      54, 72, 34, 212, 115, 11, 152, 101, 70, 42, 219, 233, 142, 66, 151,
      250, 126, 146, 141, 216, 190, 73, 50, 177, 146, 5, 52, 247, 28, 197,
      21, 59, 170, 247, 181, 89, 131, 241, 169, 182, 246, 99, 15, 36, 102,
      166, 182, 172, 197, 136, 230, 120, 60, 58, 219, 243, 149, 94, 222,
      150, 154, 194, 110, 227, 225, 112, 39, 89, 233, 112, 207, 211, 241,
      124, 174, 69, 221, 179, 107, 196, 225, 127, 167, 112, 226, 12, 242,
      16, 24, 28, 120, 182, 244, 213, 244, 153, 194, 162, 69, 160, 244,
      248, 63, 165, 141, 4, 207, 249, 193, 79, 131, 0, 169, 233, 127, 167,
      101, 151, 125, 56, 112, 111, 248, 29, 232, 90, 29, 147, 110, 169,
      146, 114, 165, 204, 71, 136, 41, 252
    };
    /**
     * A.2.8. Validation This example illustrates the process of creating a JWE
     * with RSAES-PKCS1-v1_5 for key encryption and AES_CBC_HMAC_SHA2 for
     * content encryption. These results can be used to validate JWE decryption
     * implementations for these algorithms. Note that since the
     * RSAES-PKCS1-v1_5 computation includes random values, the encryption
     * results above will not be completely reproducible. However, since the
     * AES-CBC computation is deterministic, the JWE Encrypted Ciphertext values
     * will be the same for all encryptions performed using these inputs.
     * <p>
     * Developer note: encryption result lengths are expected to match but not
     * the contents
     */
    assertEquals(encExpected.length, enc.length);

    /**
     * A.2.4. Initialization Vector Generate a random 128-bit JWE Initialization
     * Vector. In this example, the value is: [3, 22, 60, 12, 43, 67, 104, 105,
     * 108, 108, 105, 99, 111, 116, 104, 101] Encoding this JWE Initialization
     * Vector as BASE64URL(JWE Initialization Vector) gives this value:
     * AxY8DCtDaGlsbGljb3RoZQ
     */
    final byte[] initVector = TestUtil.convertUnsignedIntsToBytes(new int[]{3, 22, 60, 12, 43, 67, 104, 105, 108,
                                                                            108, 105, 99, 111, 116, 104,
                                                                            101});
    assertEquals("AxY8DCtDaGlsbGljb3RoZQ", toBase64Url(initVector));

    /**
     * A.2.5. Additional Authenticated Data Let the Additional Authenticated
     * Data encryption parameter be ASCII(BASE64URL(UTF8(JWE Protected
     * Header))). This value is: [101, 121, 74, 104, 98, 71, 99, 105, 79, 105,
     * 74, 83, 85, 48, 69, 120, 88, 122, 85, 105, 76, 67, 74, 108, 98, 109, 77,
     * 105, 79, 105, 74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84,
     * 77, 106, 85, 50, 73, 110, 48]
     */
    final byte[] aad = TestUtil.convertUnsignedIntsToBytes(new int[]{
      101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
      120, 88, 122, 85, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105,
      74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85,
      50, 73, 110, 48});
    assertArrayEquals(aad, toBase64Url(joseHeaderJson).getBytes(US_ASCII));
    /**
     * A.2.6. Content Encryption Perform authenticated encryption on the
     * plaintext with the AES_128_CBC_HMAC_SHA_256 algorithm using the CEK as
     * the encryption key, the JWE Initialization Vector, and the Additional
     * Authenticated Data value above. The steps for doing this using the values
     * from Appendix A.3 are detailed in Appendix B. The resulting ciphertext
     * is:
     */

//    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
//    Cipher cipher1 = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
//    AlgorithmParameterSpec spec = new IvParameterSpec(initVector);//  System.out.println(cekBytes.length);
    /**
     * Developer note: Additional files may need to be downloaded and copied
     * into the Java installation security directory
     * https://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters
     */
//    Key aesKey = new SecretKeySpec(cekBytes, contentEncyptionAlgorithm.getSecretKeyAlgorithm());
//    cipher1.init(Cipher.ENCRYPT_MODE, aesKey, spec);
//    cipher1.updateAAD(aad);
//    int cypherLen = getUtf8Bytes(plaintext).length; // cipher1.getOutputSize(plaintext.length());
//    byte[] cypherAndAuthTag = cipher1.doFinal(getUtf8Bytes(plaintext));
//    System.out.println("plaintext.length() = " + plaintext.length());
//    System.out.println("cypherAndAuthTag.length = " + cypherAndAuthTag.length);
//    byte[] cypher = Arrays.copyOf(cypherAndAuthTag, cypherLen);
//    byte[] authTag = Arrays.copyOfRange(cypherAndAuthTag, cypherLen, cypherAndAuthTag.length);
//    System.out.println(authTag.length);
//    assertArrayEquals(new int[]{40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,
//        75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143,
//        112, 56, 102}, TestUtil.toUnsignedInt(cypher));
//    assertArrayEquals(new int[]{246, 17, 244, 190, 4, 95, 98, 3, 231, 0, 115, 157, 242, 203, 100, 191}, TestUtil
// .toUnsignedInt(authTag));
  }

  @Test
  public void appendixA3Test() throws Exception {
    /**
     * A.3. Example JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256
     * <p>
     * This example encrypts the plaintext "Live long and prosper." to the
     * recipient using AES Key Wrap for key encryption and
     * AES_128_CBC_HMAC_SHA_256 for content encryption. The representation of
     * this plaintext (using JSON array notation) is:
     */
    final String plaintext = "Live long and prosper.";
    final byte[] plaintextBytes = plaintext.getBytes(US_ASCII);
    assertArrayEquals(new byte[]{76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
                                 112, 114, 111, 115, 112, 101, 114, 46}, plaintextBytes);
    /**
     * A.3.1. JOSE Header
     * <p>
     * The following example JWE Protected Header declares that:
     * <p>
     * o The Content Encryption Key is encrypted to the recipient using the AES
     * Key Wrap algorithm with a 128-bit key to produce the JWE Encrypted Key. o
     * Authenticated encryption is performed on the plaintext using the
     * AES_128_CBC_HMAC_SHA_256 algorithm to produce the ciphertext and the
     * Authentication Tag.
     * <p>
     * {"alg":"A128KW","enc":"A128CBC-HS256"}
     */
    final JweKeyAlgorithmType keyManagementAlgorithm = JweKeyAlgorithmType.A128KW;
    final JweEncryptionAlgorithmType contentEncyptionAlgorithm = JweEncryptionAlgorithmType.A128CBC_HS256;
    JweHeader joseHeader = new JweHeader();
    joseHeader.setAlg(keyManagementAlgorithm.getJoseAlgorithmName());
    joseHeader.setEnc(contentEncyptionAlgorithm);

    final String joseHeaderJson = toJson(joseHeader);
//    System.out.println(joseHeaderJson);
    /**
     * Encoding this JWE Protected Header as BASE64URL(UTF8(JWE Protected
     * Header)) gives this value:
     * eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0
     */
    assertEquals("eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0", toBase64Url(joseHeaderJson));

    /**
     * A.3.2. Content Encryption Key (CEK)
     * <p>
     * Generate a 256-bit random CEK. In this example, the value is:
     * <p>
     * [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
     * 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44,
     * 207]
     */
    final int[] cek = new int[]{
      4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
      206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
      44, 207
    };
    final byte[] cekBytes = TestUtil.convertUnsignedIntsToBytes(cek);
    assertArrayEquals(cek, TestUtil.toUnsignedInt(cekBytes)); // sanity check
    SecretKey cekKey = new SecretKeySpec(cekBytes, "AES");
    /**
     * A.3.3. Key Encryption
     * <p>
     * Encrypt the CEK with the shared symmetric key using the AES Key Wrap
     * algorithm to produce the JWE Encrypted Key. This example uses the
     * symmetric key represented in JSON Web Key [JWK] format below:
     */
    final String jwkJson = TestFileReader.getTestCase("/rfc7516/appendix-a/symmetric-key-appendix-a3.json");

    SymmetricJwk key = fromJson(jwkJson, SymmetricJwk.class);

    SecretKey secretKey = new SecretKeySpec(key.getK(), "AES");

    Cipher cipher = Cipher.getInstance(keyManagementAlgorithm.getJavaAlgorithm());
    cipher.init(Cipher.WRAP_MODE, secretKey);
    byte[] enc = cipher.wrap(cekKey);

//    Cipher cipher2 = Cipher.getInstance(keyManagementAlgorithm.getJavaAlgorithm());
    cipher.init(Cipher.UNWRAP_MODE, secretKey);
    SecretKey unwrapped = (SecretKey) cipher.unwrap(enc, "AES", Cipher.SECRET_KEY);

    assertEquals(unwrapped, cekKey);

    /**
     * The resulting JWE Encrypted Key value is:
     */
    int[] encExpected = new int[]{
      232, 160, 123, 211, 183, 76, 245, 132, 200, 128, 123, 75, 190, 216,
      22, 67, 201, 138, 193, 186, 9, 91, 122, 31, 246, 90, 28, 139, 57, 3,
      76, 124, 193, 11, 98, 37, 173, 61, 104, 57
    };
    assertEquals(encExpected.length, enc.length);
    assertArrayEquals(TestUtil.convertUnsignedIntsToBytes(encExpected), enc);
    /**
     * Encoding this JWE Encrypted Key as BASE64URL(JWE Encrypted Key) gives
     * this value:
     * <p>
     * 6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ
     */
    assertEquals("6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
                 toBase64Url(enc));

    /**
     * A.3.4. Initialization Vector
     * <p>
     * Generate a random 128-bit JWE Initialization Vector. In this example, the
     * value is:
     * <p>
     * [3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101]
     * <p>
     * Encoding this JWE Initialization Vector as BASE64URL(JWE Initialization
     * Vector) gives this value:
     * <p>
     * AxY8DCtDaGlsbGljb3RoZQ
     */
    final byte[] initVector = TestUtil.convertUnsignedIntsToBytes(new int[]{
      3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104,
      101});
    assertEquals("AxY8DCtDaGlsbGljb3RoZQ", toBase64Url(initVector));

    /**
     * A.3.5. Additional Authenticated Data
     * <p>
     * Let the Additional Authenticated Data encryption parameter be
     * ASCII(BASE64URL(UTF8(JWE Protected Header))). This value is:
     * <p>
     * [101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52, 83,
     * 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66, 77, 84,
     * 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73, 110, 48]
     */
    final byte[] aad = TestUtil.convertUnsignedIntsToBytes(new int[]{
      101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52,
      83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66,
      77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73,
      110, 48});
    assertArrayEquals(aad, toBase64Url(joseHeaderJson).getBytes(US_ASCII));
    /**
     * A.3.6. Content Encryption
     * <p>
     * Perform authenticated encryption on the plaintext with the
     * AES_128_CBC_HMAC_SHA_256 algorithm using the CEK as the encryption key,
     * the JWE Initialization Vector, and the Additional Authenticated Data
     * value above. The steps for doing this using the values from this example
     * are detailed in Appendix B. The resulting ciphertext is:
     * <p>
     * [40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6, 75,
     * 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143, 112, 56,
     * 102]
     * <p>
     * The resulting Authentication Tag value is:
     * <p>
     * [83, 73, 191, 98, 104, 205, 211, 128, 201, 189, 199, 133, 32, 38, 194,
     * 85]
     */
    final byte[] ciphertext = TestUtil.convertUnsignedIntsToBytes(new int[]{
      40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,
      75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143,
      112, 56, 102});
    final byte[] authTag = TestUtil.convertUnsignedIntsToBytes(new int[]{
      83, 73, 191, 98, 104, 205, 211, 128, 201, 189, 199, 133, 32, 38,
      194, 85});
    /**
     * Encoding this JWE Ciphertext as BASE64URL(JWE Ciphertext) gives this
     * value:
     * <p>
     * KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY
     * <p>
     * Encoding this JWE Authentication Tag as BASE64URL(JWE Authentication Tag)
     * gives this value:
     * <p>
     * U0m_YmjN04DJvceFICbCVQ
     */
    assertEquals("KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY", toBase64Url(ciphertext));
    assertEquals("U0m_YmjN04DJvceFICbCVQ", toBase64Url(authTag));

    byte[] secondHalf = Arrays.copyOfRange(cekBytes, cekBytes.length / 2, cekBytes.length);

    SecretKey cekKeyHalf = new SecretKeySpec(secondHalf, "AES");

    cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, cekKeyHalf, new IvParameterSpec(initVector));
    byte[] calculatedCiphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.US_ASCII));

    assertEquals(ciphertext.length, calculatedCiphertext.length);
    assertArrayEquals(ciphertext, calculatedCiphertext);

    long l = aad.length * 8;
    byte[] al = new byte[8];
    for (int i = 7; i >= 0; i--) {
      al[i] = (byte) (l & 0xFF);
      l >>= 8;
    }

    byte[] macInput = concatenate(aad, initVector, ciphertext, al);
    Key macKey = new SecretKeySpec(Arrays.copyOf(cekBytes, cekBytes.length / 2), "AES");
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(macKey);

    byte[] hmac = mac.doFinal(macInput);
    byte[] calculatedAuthTag = Arrays.copyOf(hmac, 16);

    assertEquals(authTag.length, calculatedAuthTag.length);
    assertArrayEquals(authTag, calculatedAuthTag);

    Encrypter encrypter = new DefaultEncrypter(DefaultEncrypter.Configuration.AES_128_CBC_HMAC_SHA_256);
    EncryptionResult encryptionResult = encrypter.encrypt(plaintextBytes, initVector, aad,
        new SecretKeySpec(cekBytes, encrypter.getSecretKeyAlgorithm()));

    assertArrayEquals(aad, encryptionResult.getAad());
    assertArrayEquals(initVector, encryptionResult.getIv());
    assertArrayEquals(ciphertext, encryptionResult.getCiphertext());
    assertArrayEquals(authTag, encryptionResult.getAuthTag());

    byte[] decrypted = encrypter.decrypt(ciphertext, initVector, aad, authTag,
        new SecretKeySpec(cekBytes, encrypter.getSecretKeyAlgorithm()));

    assertArrayEquals(plaintextBytes, decrypted);
  }

  /**
   * Generate random plaintext and AAD, encrypt them, then try to decrypt with either an incorrect AAD
   * or an incorrect key and confirm that the operation fails. Failure is indicated either by
   * a null result or a GeneralSecurityException thrown. That is, when expecting failure, both results indicate
   * success.
   */
  @Test
  public void testAllAlgorithms() {
    byte[] plaintext = TestUtil.createRandomString(100).getBytes();
    byte[] aad = TestUtil.createRandomString(20).getBytes();

    for (JweEncryptionAlgorithmType eEncryptionAlgo : JweEncryptionAlgorithmType.values()) {
      final Encrypter encrypter = eEncryptionAlgo.getEncrypter();
      Key key = null;
      EncryptionResult result = null;
      byte[] decrypted = new byte[0];
      /**
       * Encryption is expected to succeed. A GeneralSecurityException at this step would indicate
       * a bug or problems with JCA algorithm availability.
       */
      try {
        key = encrypter.generateKey();
        result = eEncryptionAlgo.getEncrypter().encrypt(plaintext, null, aad, key);
        decrypted = encrypter.decrypt(result.getCiphertext(), result.getIv(), aad, result.getAuthTag(), key);
      } catch (GeneralSecurityException e) {
        fail();
      }
      assertArrayEquals(plaintext, decrypted);

      for (int i = 0; i < 1000; i++) {
        /**
         * Check if changing the AAD makes decryption unsuccessful, i.e.
         * result is null.
         */
        try {
          byte[] alteredAad = TestUtil.getAlteredBytes(aad);
          assertTrue(!Arrays.equals(aad, alteredAad));
          decrypted = encrypter.decrypt(result.getCiphertext(), result.getIv(), alteredAad,
              result.getAuthTag(), key);
          assertTrue(decrypted == null || !Arrays.equals(plaintext, decrypted));
        } catch (GeneralSecurityException e) {
          // expected
        }
        /**
         * Check if changing the key makes decryption unsuccessful, i.e.
         * result is null. Developer note: occasionally the decrypted value is
         * not null but, as expected, not equal to the original plaintext
         */
        Key fakeKey = new SecretKeySpec(TestUtil.getAlteredBytes(key.getEncoded()), "AES");
        try {
          decrypted = encrypter.decrypt(result.getCiphertext(), result.getIv(), aad, result.getAuthTag(), fakeKey);
          assertTrue(decrypted == null || !Arrays.equals(plaintext, decrypted));
        } catch (GeneralSecurityException e) {
          // expected
        }
      }
    }

  }

  @Test
  public void testAesGcmEncrypter() throws Exception {
    testEncrypter(new AesGcmEncrypter(128));
    testEncrypter(new AesGcmEncrypter(192));
    testEncrypter(new AesGcmEncrypter(256));
  }

  @Test
  public void testAesCbcHmacSha2Encrypter() throws Exception {
    testEncrypter(new DefaultEncrypter(DefaultEncrypter.Configuration.AES_128_CBC_HMAC_SHA_256));
    testEncrypter(new DefaultEncrypter(DefaultEncrypter.Configuration.AES_192_CBC_HMAC_SHA_384));
    testEncrypter(new DefaultEncrypter(DefaultEncrypter.Configuration.AES_256_CBC_HMAC_SHA_512));
  }

  public void testEncrypter(Encrypter encrypter) throws GeneralSecurityException {
    byte[] payload = ("      156, 223, 120, 156, 115, 232, 150, 209, 145, 133, 104, 112, 237, 156,\n"
                      + "      116, 250, 65, 102, 212, 210, 103, 240, 177, 61, 93, 40, 71, 231, 223,\n"
                      + "      226, 240, 157, 15, 31, 150, 89, 200, 215, 198, 203, 108, 70, 117, 66,\n"
                      + "      212, 238, 193, 205, 23, 161, 169, 218, 243, 203, 128, 214, 127, 253,\n"
                      + "      215, 139, 43, 17, 135, 103, 179, 220, 28, 2, 212, 206, 131, 158, 128,\n"
                      + "      66, 62, 240, 78, 186, 141, 125, 132, 227, 60, 137, 43, 31, 152, 199,\n"
                      + "      54, 72, 34, 212, 115, 11, 152, 101, 70, 42, 219, 233, 142, 66, 151,\n"
                      + "      250, 126, 146, 141, 216, 190, 73, 50, 177, 146, 5, 52, 247, 28, 197,\n"
                      + "      21, 59, 170, 247, 181, 89, 131, 241, 169, 182, 246, 99, 15, 36, 102").getBytes(StandardCharsets.UTF_8);
    byte[] aad = "some additional authenticated data for testing".getBytes(StandardCharsets.UTF_8);

    Key key = encrypter.generateKey();

    EncryptionResult result = encrypter.encrypt(payload, null, aad, key);

    assertArrayEquals(aad, result.getAad());

    byte[] decrypted = encrypter.decrypt(result.getCiphertext(), result.getIv(), aad, result.getAuthTag(), key);
    assertArrayEquals(payload, decrypted);
  }
}
