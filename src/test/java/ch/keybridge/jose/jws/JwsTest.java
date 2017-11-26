package ch.keybridge.jose.jws;

import ch.keybridge.jose.util.EncodingUtility;
import ch.keybridge.jose.util.CryptographyUtility;
import ch.keybridge.TestUtil;
import ch.keybridge.jose.algorithm.ESignatureAlgorithm;
import ch.keybridge.jose.io.JsonUtility;
import ch.keybridge.jose.jwk.JWK;
import ch.keybridge.jose.jwk.JwkSymmetricKey;
import org.junit.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.util.Base64;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class JwsTest {


  @Test
  public void encodingTest() throws Exception {
    /**
     * A.1.  Example JWS Using HMAC SHA-256
     *
     A.1.1.  Encoding

     The following example JWS Protected Header declares that the data
     structure is a JWT [JWT] and the JWS Signing Input is secured using
     the HMAC SHA-256 algorithm.
     <pre>
     {"typ":"JWT",
     "alg":"HS256"}
     </pre>
     To remove potential ambiguities in the representation of the JSON
     object above, the actual octet sequence representing UTF8(JWS
     Protected Header) used in this example is also included below.  (Note
     that ambiguities can arise due to differing platform representations
     of line breaks (CRLF versus LF), differing spacing at the beginning
     and ends of lines, whether the last line has a terminating line break
     or not, and other causes.  In the representation used in this
     example, the first line has no leading or trailing spaces, a CRLF
     line break (13, 10) occurs between the first and second lines, the
     second line has one leading space (32) and no trailing spaces, and
     the last line does not have a terminating line break.)
     */
    final String jwsProtectedHeader = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}";
    final byte[] jwsProtectedHeaderBytesUTF8 = jwsProtectedHeader.getBytes(Charset.forName("UTF-8"));
    /**
     * The octets representing UTF8(JWS Protected Header) in this example (using JSON
     array notation) are:
     [123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32,
     34, 97, 108, 103, 34, 58, 34, 72, 83, 50, 53, 54, 34, 125]
     */
    assertArrayEquals(new byte[]{123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32,
        34, 97, 108, 103, 34, 58, 34, 72, 83, 50, 53, 54, 34, 125}, jwsProtectedHeaderBytesUTF8);
    /**
     * Encoding this JWS Protected Header as BASE64URL(UTF8(JWS Protected
     Header)) gives this value:
     eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9
     */
    final String jwsProtectedHeaderEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString
        (jwsProtectedHeaderBytesUTF8);
    assertEquals("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9", jwsProtectedHeaderEncoded);

    /**
     * The JWS Payload used in this example is the octets of the UTF-8
     representation of the JSON object below.  (Note that the payload can
     be any base64url-encoded octet sequence and need not be a base64url-
     encoded JSON object.)
     {"iss":"joe",
     "exp":1300819380,
     "http://example.com/is_root":true}
     */
    final String jwsPayload = "{\"iss\":\"joe\",\r\n" +
        " \"exp\":1300819380,\r\n" +
        " \"http://example.com/is_root\":true}";
    /**
     *    The following octet sequence, which is the UTF-8 representation used
     in this example for the JSON object above, is the JWS Payload:
     [123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10,
     32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56,
     48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97,
     109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111,
     111, 116, 34, 58, 116, 114, 117, 101, 125]

     */
    final byte[] jwsPayloadBytesUTF8 = jwsPayload.getBytes(Charset.forName("UTF-8"));
    assertArrayEquals(new byte[]{123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10,
        32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56,
        48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97,
        109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111,
        111, 116, 34, 58, 116, 114, 117, 101, 125}, jwsPayloadBytesUTF8);
    /**
     * Encoding this JWS Payload as BASE64URL(UTF8(JWS Payload)) gives this
     value (with line breaks for display purposes only):
     eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
     cGxlLmNvbS9pc19yb290Ijp0cnVlfQ
     */
    final String jwsPayloadEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(jwsPayloadBytesUTF8);
    assertEquals("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
        jwsPayloadEncoded);

    /**
     *
     Combining these as BASE64URL(UTF8(JWS Protected Header)) || ’.’ ||
     BASE64URL(JWS Payload) gives this string (with line breaks for
     display purposes only):
     eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9
     .
     eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
     cGxlLmNvbS9pc19yb290Ijp0cnVlfQ
     */
    final String jwsSigningInput = jwsProtectedHeaderEncoded + '.' + jwsPayloadEncoded;

    /**
     * The resulting JWS Signing Input value, which is the ASCII
     representation of above string, is the following octet sequence
     (using JSON array notation):
     [101, 121, 74, 48, 101, 88, 65, 105, 79, 105, 74, 75, 86, 49, 81,
     105, 76, 65, 48, 75, 73, 67, 74, 104, 98, 71, 99, 105, 79, 105, 74,
     73, 85, 122, 73, 49, 78, 105, 74, 57, 46, 101, 121, 74, 112, 99, 51,
     77, 105, 79, 105, 74, 113, 98, 50, 85, 105, 76, 65, 48, 75, 73, 67,
     74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65, 52, 77, 84,
     107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100,
     72, 65, 54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76,
     109, 78, 118, 98, 83, 57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73,
     106, 112, 48, 99, 110, 86, 108, 102, 81]
     */
    assertArrayEquals(new byte[]{101, 121, 74, 48, 101, 88, 65, 105, 79, 105, 74, 75, 86, 49, 81,
        105, 76, 65, 48, 75, 73, 67, 74, 104, 98, 71, 99, 105, 79, 105, 74,
        73, 85, 122, 73, 49, 78, 105, 74, 57, 46, 101, 121, 74, 112, 99, 51,
        77, 105, 79, 105, 74, 113, 98, 50, 85, 105, 76, 65, 48, 75, 73, 67,
        74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65, 52, 77, 84,
        107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100,
        72, 65, 54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76,
        109, 78, 118, 98, 83, 57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73,
        106, 112, 48, 99, 110, 86, 108, 102, 81}, jwsSigningInput.getBytes(Charset.forName("UTF-8")));

    /**
     * HMACs are generated using keys.  This example uses the symmetric key
     represented in JSON Web Key [JWK] format below (with line breaks
     within values for display purposes only):
     {"kty":"oct",
     "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75
     aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
     }
     */
    JsonUtility<JWK> readerWriter = new JsonUtility<>(JWK.class);
    JwkSymmetricKey key = (JwkSymmetricKey) readerWriter.fromJson("{\"kty\":\"oct\",\n" +
        "\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}");

    Mac mac = Mac.getInstance("HmacSHA256");
    SecretKeySpec secretKeySpec = new SecretKeySpec(key.getK(), "HmacSHA256");
    mac.init(secretKeySpec);

    byte[] hmac = mac.doFinal(jwsSigningInput.getBytes(Charset.forName("UTF-8")));
    /**
     * Running the HMAC SHA-256 algorithm on the JWS Signing Input with this
     key yields this JWS Signature octet sequence:
     [116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
     187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
     132, 141, 121]
     */
    assertArrayEquals(new int[]{116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
        187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
        132, 141, 121}, TestUtil.toUnsignedInt(hmac));
    assertArrayEquals(TestUtil.convertUnsignedIntsToBytes(new int[]{116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
        187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
        132, 141, 121}), hmac);
    /**
     * Encoding this JWS Signature as BASE64URL(JWS Signature) gives this
     value:
     dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
     */
    final String expectedSignature = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    assertEquals(expectedSignature, EncodingUtility.encodeBase64Url(hmac));
    /**
     * Check whether the EncryptionUtility returns the same result
     */
    byte[] signatureUtility = CryptographyUtility.sign(jwsSigningInput.getBytes(EncodingUtility.UTF8), key, ESignatureAlgorithm.HS256);
    assertEquals(expectedSignature, EncodingUtility.encodeBase64Url(signatureUtility));
  }

}