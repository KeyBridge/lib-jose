package ch.keybridge.jose.jwk;

import ch.keybridge.TestFileReader;
import ch.keybridge.jose.io.JsonUtility;
import org.junit.Test;

import javax.xml.bind.JAXBException;
import java.math.BigInteger;
import java.util.Base64;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class JwkTest {
  private JsonUtility<JWK> readerWriter;
  private JsonUtility<JWKSet> readerWriterWKS;
  @org.junit.Before
  public void setUp() throws Exception {
    readerWriter = new JsonUtility<>(JWK.class);
    readerWriterWKS = new JsonUtility<>(JWKSet.class);//, JwkRsaKey.class, JWK.class);
  }

  @Test
  public void ecPublicKeyTest() throws JAXBException {
    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/ec-public-key.json");
    System.out.println(json);
    JWK key = readerWriter.fromJson(json);
    assertTrue(key instanceof JwkEcKey);
    JwkEcKey ecKey = (JwkEcKey)key;
    assertEquals("P-521", ecKey.getCrv());
    assertEquals("sig", ecKey.getUse());
    assertEquals("bilbo.baggins@hobbiton.example", ecKey.getKid());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt")), ecKey.getX());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1")), ecKey.getY());
    assertEquals(null, ecKey.getD());

    JwkEcKey keyReconverted = (JwkEcKey)readerWriter.fromJson(readerWriter.toJson(ecKey));
    assertEquals(ecKey, keyReconverted);
  }

  @Test
  public void ecPrivateKeyTest() throws JAXBException {
    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/ec-private-key.json");
    System.out.println(json);
    JWK key = readerWriter.fromJson(json);
    assertTrue(key instanceof JwkEcKey);
    JwkEcKey ecKey = (JwkEcKey)key;
    assertEquals("P-521", ecKey.getCrv());
    assertEquals("sig", ecKey.getUse());
    assertEquals("bilbo.baggins@hobbiton.example", ecKey.getKid());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt")), ecKey.getX());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1")), ecKey.getY());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt")), ecKey.getD());

    JwkEcKey keyReconverted = (JwkEcKey)readerWriter.fromJson(readerWriter.toJson(ecKey));
    assertEquals(ecKey, keyReconverted);
  }

  @Test
  public void rsaPublicKeyTest() throws JAXBException {
    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/rsa-public-key.json");
    System.out.println(json);
    JWK key = readerWriter.fromJson(json);
    assertTrue(key instanceof JwkRsaKey);
    JwkRsaKey rsaKey = (JwkRsaKey) key;
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw")), rsaKey.getModulus());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("AQAB")), rsaKey.getPublicExponent());
    assertEquals("sig", rsaKey.getUse());
    assertEquals("bilbo.baggins@hobbiton.example", rsaKey.getKid());

    JwkRsaKey keyReconverted = (JwkRsaKey)readerWriter.fromJson(readerWriter.toJson(rsaKey));
    assertEquals(rsaKey, keyReconverted);
  }

  @Test
  public void rsaPrivateKeyTest() throws JAXBException {
    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/rsa-private-key.json");
    System.out.println(json);
    JWK key = readerWriter.fromJson(json);
    assertTrue(key instanceof JwkRsaKey);
    JwkRsaKey rsaKey = (JwkRsaKey) key;
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw")), rsaKey.getModulus());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ")), rsaKey.getPrivateExponent());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("AQAB")), rsaKey.getPublicExponent());
    assertEquals("sig", rsaKey.getUse());
    assertEquals("bilbo.baggins@hobbiton.example", rsaKey.getKid());

    JwkRsaKey keyReconverted = (JwkRsaKey)readerWriter.fromJson(readerWriter.toJson(rsaKey));
    assertEquals(rsaKey, keyReconverted);
  }

  @Test
  public void jwkPublicKeySetTest() throws JAXBException {
    String json = TestFileReader.getTestCase("/rfc7517/appendix-a/public-keys.json");
    System.out.println(json);
    JWKSet deserialized = readerWriterWKS.fromJson(json);
    assertEquals(2, deserialized.keys.size());
    assertTrue(deserialized.keys.get(0) instanceof JwkEcKey);
    JwkEcKey ecKey = (JwkEcKey)deserialized.keys.get(0);
    assertEquals("P-256", ecKey.getCrv());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")), ecKey.getX());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")), ecKey.getY());
    assertEquals("enc", ecKey.getUse());
    assertEquals("1", ecKey.getKid());

    assertTrue(deserialized.keys.get(1) instanceof JwkRsaKey);
    JwkRsaKey rsaKey = (JwkRsaKey) deserialized.keys.get(1);
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")), rsaKey.getModulus());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("AQAB")), rsaKey.getPublicExponent());
    assertEquals("RS256", rsaKey.getAlg());
    assertEquals("2011-04-29", rsaKey.getKid());

    JWKSet reconverted = readerWriterWKS.fromJson(readerWriterWKS.toJson(deserialized));
    assertEquals(deserialized, reconverted);
  }

  @Test
  public void jwkPrivateKeySetTest() throws JAXBException {
    String json = TestFileReader.getTestCase("/rfc7517/appendix-a/private-keys.json");
    System.out.println(json);
    JWKSet deserialized = readerWriterWKS.fromJson(json);
    assertEquals(2, deserialized.keys.size());
    assertTrue(deserialized.keys.get(0) instanceof JwkEcKey);
    JwkEcKey ecKey = (JwkEcKey)deserialized.keys.get(0);
    assertEquals("P-256", ecKey.getCrv());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")), ecKey.getX());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")), ecKey.getY());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE")), ecKey.getD());
    assertEquals("enc", ecKey.getUse());
    assertEquals("1", ecKey.getKid());

    assertTrue(deserialized.keys.get(1) instanceof JwkRsaKey);
    JwkRsaKey rsaKey = (JwkRsaKey) deserialized.keys.get(1);
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")), rsaKey.getModulus());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("AQAB")), rsaKey.getPublicExponent());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q")), rsaKey.getPrivateExponent());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs")), rsaKey.getP());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk")), rsaKey.getQ());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0")), rsaKey.getDp());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk")), rsaKey.getDq());
    assertEquals(new BigInteger(1, Base64.getUrlDecoder().decode("GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU")), rsaKey.getQi());
    assertEquals("RS256", rsaKey.getAlg());
    assertEquals("2011-04-29", rsaKey.getKid());

    JWKSet reconverted = readerWriterWKS.fromJson(readerWriterWKS.toJson(deserialized));
    assertEquals(deserialized, reconverted);
  }
}