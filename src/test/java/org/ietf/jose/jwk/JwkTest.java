package org.ietf.jose.jwk;

import java.io.IOException;
import java.math.BigInteger;
import org.ietf.TestFileReader;
import org.ietf.jose.jwk.key.*;
import org.ietf.jose.util.Base64Utility;
import org.ietf.jose.util.JsonbUtility;
import org.junit.Test;

import static org.junit.Assert.*;

public class JwkTest {

  @Test
  public void ecPublicKeyTest() throws IOException {
    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/ec-public-key.json");
    AbstractJwk key = new JsonbUtility().unmarshal(json, EllipticCurvePublicJwk.class);
    assertTrue(key instanceof EllipticCurvePublicJwk);
    EllipticCurvePublicJwk ecKey = (EllipticCurvePublicJwk) key;
    assertEquals(EllipticCurveType.P_521, ecKey.getCrv());
    assertEquals(PublicKeyUseType.sig, ecKey.getUse());
    assertEquals("bilbo.baggins@hobbiton.example", ecKey.getKid());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt")), ecKey.getX());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1")), ecKey.getY());
//    assertNull(ecKey.getD());

    EllipticCurvePublicJwk keyReconverted = (EllipticCurvePublicJwk) new JsonbUtility().unmarshal(new JsonbUtility().marshal(ecKey), AbstractJwk.class);
    assertEquals(ecKey, keyReconverted);
  }

  @Test
  public void ecPrivateKeyTest() throws IOException {
    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/ec-private-key.json");
    AbstractJwk key = new JsonbUtility().unmarshal(json, EllipticCurvePrivateJwk.class);
    assertTrue(key instanceof EllipticCurvePrivateJwk);
    EllipticCurvePrivateJwk ecKey = (EllipticCurvePrivateJwk) key;
    assertEquals(EllipticCurveType.P_521, ecKey.getCrv());
    assertEquals(PublicKeyUseType.sig, ecKey.getUse());
    assertEquals("bilbo.baggins@hobbiton.example", ecKey.getKid());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt")), ecKey.getX());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1")), ecKey.getY());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt")), ecKey.getD());

    EllipticCurvePrivateJwk keyReconverted = new JsonbUtility().unmarshal(new JsonbUtility().marshal(ecKey), EllipticCurvePrivateJwk.class);
    assertEquals(ecKey, keyReconverted);
  }

  @Test
  public void rsaPublicKeyTest() throws IOException {
    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/rsa-public-key.json");
    AbstractJwk key = new JsonbUtility().unmarshal(json, AbstractJwk.class);
    assertTrue(key instanceof RsaPublicJwk);
    RsaPublicJwk rsaKey = (RsaPublicJwk) key;
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O"
                                + "-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL"
                                + "-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe"
                                + "-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3"
                                + "-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw")), rsaKey
                 .getModulus());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AQAB")), rsaKey.getPublicExponent());
    assertEquals(PublicKeyUseType.sig, rsaKey.getUse());
    assertEquals("bilbo.baggins@hobbiton.example", rsaKey.getKid());

    RsaPublicJwk keyReconverted = (RsaPublicJwk) new JsonbUtility().unmarshal(new JsonbUtility().marshal(rsaKey), AbstractJwk.class);
    assertEquals(rsaKey, keyReconverted);
  }

  @Test
  public void rsaPrivateKeyTest() throws IOException {
    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/rsa-private-key.json");
    AbstractJwk key = new JsonbUtility().unmarshal(json, AbstractJwk.class);
    assertTrue(key instanceof RsaPrivateJwk);
    RsaPrivateJwk rsaKey = (RsaPrivateJwk) key;
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O"
                                + "-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL"
                                + "-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe"
                                + "-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3"
                                + "-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw")), rsaKey
                 .getModulus());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ"
                                + "-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA"
                                + "-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h"
                                + "-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ")
    ), rsaKey.getPrivateExponent());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AQAB")), rsaKey.getPublicExponent());
    assertEquals(PublicKeyUseType.sig, rsaKey.getUse());
    assertEquals("bilbo.baggins@hobbiton.example", rsaKey.getKid());

    RsaPrivateJwk keyReconverted = (RsaPrivateJwk) new JsonbUtility().unmarshal(new JsonbUtility().marshal(rsaKey), AbstractJwk.class);
    assertEquals(rsaKey, keyReconverted);
  }

  @Test
  public void jwkPublicKeySetTest() throws IOException {
    String json = TestFileReader.getTestCase("/rfc7517/appendix-a/public-keys.json");
    JwkSet deserialized = new JsonbUtility().unmarshal(json, JwkSet.class);
    assertEquals(2, deserialized.getKeys().size());
    assertTrue(deserialized.getKeys().get(0) instanceof EllipticCurvePublicJwk);
    EllipticCurvePublicJwk ecKey = (EllipticCurvePublicJwk) deserialized.getKeys().get(0);
    assertEquals(EllipticCurveType.P_256, ecKey.getCrv());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")), ecKey.getX());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")), ecKey.getY());
    assertEquals(PublicKeyUseType.enc, ecKey.getUse());
    assertEquals("1", ecKey.getKid());

    assertTrue(deserialized.getKeys().get(1) instanceof RsaPublicJwk);
    RsaPublicJwk rsaKey = (RsaPublicJwk) deserialized.getKeys().get(1);
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")), rsaKey.getModulus());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AQAB")), rsaKey.getPublicExponent());
    assertEquals("RS256", rsaKey.getAlg());
    assertEquals("2011-04-29", rsaKey.getKid());

    JwkSet reconverted = new JsonbUtility().unmarshal(new JsonbUtility().marshal(deserialized), JwkSet.class);
    assertEquals(deserialized, reconverted);
  }

  @Test
  public void jwkPrivateKeySetTest() throws IOException {
    String json = TestFileReader.getTestCase("/rfc7517/appendix-a/private-keys.json");
    JwkSet deserialized = new JsonbUtility().unmarshal(json, JwkSet.class);
    assertEquals(2, deserialized.getKeys().size());

    assertTrue(deserialized.getKeys().get(0) instanceof EllipticCurvePrivateJwk);
    EllipticCurvePrivateJwk ecKey = (EllipticCurvePrivateJwk) deserialized.getKeys().get(0);
    assertEquals(EllipticCurveType.P_256, ecKey.getCrv());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")), ecKey.getX());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")), ecKey.getY());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE")), ecKey.getD());
    assertEquals(PublicKeyUseType.enc, ecKey.getUse());
    assertEquals("1", ecKey.getKid());

    assertTrue(deserialized.getKeys().get(1) instanceof RsaPrivateJwk);
    RsaPrivateJwk rsaKey = (RsaPrivateJwk) deserialized.getKeys().get(1);
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")), rsaKey.getModulus());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AQAB")), rsaKey.getPublicExponent());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH"
                                + "-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q")), rsaKey.getPrivateExponent());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R"
                                + "-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs")), rsaKey.getP());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("3dfOR9cuYq-0S"
                                + "-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk")), rsaKey.getQ());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0")), rsaKey.getDp());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk")), rsaKey.getDq());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI"
                                + "-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU")), rsaKey.getQi());
    assertEquals("RS256", rsaKey.getAlg());
    assertEquals("2011-04-29", rsaKey.getKid());

    JwkSet reconverted = new JsonbUtility().unmarshal(new JsonbUtility().marshal(deserialized), JwkSet.class);
    assertEquals(deserialized, reconverted);
  }
}
