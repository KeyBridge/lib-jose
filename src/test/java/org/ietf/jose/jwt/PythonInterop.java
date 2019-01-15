package org.ietf.jose.jwt;

import org.ietf.jose.jwa.JweKeyAlgorithmType;
import org.ietf.jose.jwe.JsonWebEncryption;
import org.ietf.jose.jwe.JweBuilder;
import org.ietf.jose.jwe.JweDecryptor;
import org.ietf.jose.jwk.JsonWebKey;
import org.ietf.jose.jwk.key.RsaPrivateJwk;
import org.ietf.jose.jws.JsonWebSignature;
import org.ietf.jose.jws.SignatureValidator;
import org.ietf.jose.util.JsonMarshaller;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;


/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 01/06/2018
 */
public class PythonInterop {

  /**
   * Verify the example in src/test/python/sign-output.txt
   * @throws Exception
   */
  @Test
  public void testHmacSignature() throws Exception {
    String keyJson = "{\"k\":\"kGpikVaixila7_ItL2TUntsXseU6nsiDB70rypC7Pnc\",\"kty\":\"oct\"}";
    JsonWebKey jwk = JsonMarshaller.fromJson(keyJson, JsonWebKey.class);

    String jwsJson = "{\"header\":{\"kid\":\"I02Tv_pkGNw_rYNYERVA7QV6SxvmJmuRg32POLdPt5c\"}," +
        "\"payload\":\"RGVtbyBJbnRlZ3JpdHkgcHJvdGVjdGVkIG1lc3NhZ2U\",\"protected\":\"eyJhbGciOiJIUzI1NiJ9\"," +
        "\"signature\":\"MMmrjdjBxnUrqcFt9iMZlmRE3VRw-0J6Dd3uUx-qBvc\"}";
    JsonWebSignature jws = JsonWebSignature.fromJson(jwsJson);
    Assert.assertEquals(1, jws.getSignatures().size());

    Assert.assertTrue(SignatureValidator.isValid(jws.getSignatures().get(0), jwk));
    Assert.assertEquals("Demo Integrity protected message", jws.getStringPayload());
  }

  @Test
  public void name() throws Exception {
    KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    JsonWebEncryption encryption = JweBuilder.getInstance()
        .withKeyManagementAlgorithm(JweKeyAlgorithmType.RSA_OAEP)
        .withStringPayload("hi")
        .buildJweJsonFlattened(kp.getPublic(), "someKeyId");

    System.out.println(encryption.toJson());

    byte[] bytes = JweDecryptor.createFor(encryption)
        .decrypt(kp.getPrivate())
        .getAsBytes();
    System.out.println(Arrays.toString(bytes));
  }

  @Test
  public void name2() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(1024); // speedy generation, but not secure anymore
    KeyPair kp = kpg.generateKeyPair();
    RSAPublicKey pubkey = (RSAPublicKey) kp.getPublic();
    RSAPrivateKey privkey = (RSAPrivateKey) kp.getPrivate();

// --- encrypt given algorithm string
    Cipher oaepFromAlgo = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
    oaepFromAlgo.init(Cipher.ENCRYPT_MODE, pubkey);
    byte[] ct = oaepFromAlgo.doFinal("owlstead".getBytes(StandardCharsets.UTF_8));

// --- decrypt given OAEPParameterSpec
    Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/OAEPPadding");
    OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource
        .PSpecified.DEFAULT);
    oaepFromInit.init(Cipher.DECRYPT_MODE, privkey, oaepParams);
    byte[] pt = oaepFromInit.doFinal(ct);
    System.out.println(new String(pt, StandardCharsets.UTF_8));
  }

  /**
   * Test result in src/test/python/encrypt-output.txt
   */
  @Test
  public void testEncrypted() throws Exception {
    String privateKeyJson = "{\"d\":\"bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS" +
        "-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA" +
        "-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h" +
        "-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ\",\n" +
        "\"dp\":\"B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3" +
        "-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX59ehik\",\n" +
        "\"dq\":\"CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT" +
        "-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf" +
        "-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8\",\n" +
        "\"e\":\"AQAB\",\n" +
        "\"kid\":\"bilbo.baggins@hobbiton.example\",\n" +
        "\"kty\":\"RSA\",\n" +
        "\"n\":\"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O" +
        "-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL" +
        "-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe" +
        "-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3" +
        "-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw\",\n" +
        "\"p\":\"3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_" +
        "-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt" +
        "-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k\",\n" +
        "\"q\":\"uKE2dh" +
        "-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc\",\n" +
        "\"qi\":\"3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe" +
        "-7ZMaQj8VfBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4\"}\n";
    JsonWebKey jwk = JsonMarshaller.fromJson(privateKeyJson, JsonWebKey.class);

    String jweJson = "{\"ciphertext\":\"1OW7iUv0idBJhue_Uz2rw1YJQaeaNb4ToruDvst5ZgQ\",\n" +
        "\"encrypted_key\":\"Mo4ddtxpVz4spV_yixhqS9tUQBZTcJ2mhgpuUOI38kArWZlpl3JYPEV-J2uv76hqWQ4j5x8" +
        "-W4C1wWtQDOkCLJMNnQYnPL4JvuzqILN8ob27XHUyNa7lKaMkuqfuz2YIjJEtXbUegjW1lug-fseSN4pe0V" +
        "-mT5D9YYHP2GVBkcWWTy8vIiZtqPvv0oVAcqSRLOCWMYAW4jZsh2g4ZQGBCavzWxBgi_eC0_ePseU4vNADOONq3EAgm4r0Fpk_AzNE1ashILoB-y79LcR_6RexHBC6B90PqWi_wy1rUNeDPaD-zuTx8Yx2qk7kc9zIRqNi5oGCisG7THztC0MDRO3Qsw\",\n" +
        "\"iv\":\"nrnEuUguvN1y9EuLQzCOOg\",\n" +
        "\"protected" +
        "\":\"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoiOWpnNDZXQjNyUl9BSEQtRUJYZE43Y0JrSDFXT3UwdEEzTTlmbTIxbXFUSSIsInR5cCI6IkpXRSJ9\",\n" +
        "\"tag\":\"fluLRViibE5CQd4pkEfvAsUsPcp5feMKqTZg8jfqQnQ\"}";
    JsonWebEncryption jwe = JsonWebEncryption.fromJson(jweJson);

    System.out.println("jwe.getProtectedHeader() = " + jwe.getProtectedHeader());

    byte[] bytes = JweDecryptor.createFor(jwe)
        .decrypt(((RsaPrivateJwk)jwk).getPrivateKey())
        .getAsBytes();

    System.out.println(Arrays.toString(bytes));

  }
}
