/*
 * Copyright 2020 Key Bridge. All rights reserved. Use is subject to license
 * terms.
 *
 * This software code is protected by Copyrights and remains the property of
 * Key Bridge and its suppliers, if any. Key Bridge reserves all rights in and to
 * Copyrights and no license is granted under Copyrights in this Software
 * License Agreement.
 *
 * Key Bridge generally licenses Copyrights for commercialization pursuant to
 * the terms of either a Standard Software Source Code License Agreement or a
 * Standard Product License Agreement. A copy of either Agreement can be
 * obtained upon request by sending an email to info@keybridgewireless.com.
 *
 * All information contained herein is the property of Key Bridge and its
 * suppliers, if any. The intellectual and technical concepts contained herein
 * are proprietary.
 */
package org.ietf.jose.adapter;

import java.math.BigInteger;
import org.ietf.TestFileReader;
import org.ietf.jose.jwk.KeyType;
import org.ietf.jose.jwk.PublicKeyUseType;
import org.ietf.jose.jwk.key.AbstractJwk;
import org.ietf.jose.jwk.key.EllipticCurveJwk;
import org.ietf.jose.jwk.key.RsaPrivateJwk;
import org.ietf.jose.jwk.key.RsaPublicJwk;
import org.ietf.jose.util.Base64Utility;
import org.ietf.jose.util.JsonbUtility;
import org.junit.*;

import static org.junit.Assert.assertEquals;

/**
 *
 * @author Key Bridge
 */
public class JsonbJwkAdapterTest {

  private static JsonbJwkAdapter adapter;

  public JsonbJwkAdapterTest() {
  }

  @BeforeClass
  public static void setUpClass() {
    adapter = new JsonbJwkAdapter();
  }

  @AfterClass
  public static void tearDownClass() {
  }

  @Before
  public void setUp() {
  }

  @After
  public void tearDown() {
  }

  @Test
  public void testEcPublicKey() throws Exception {
    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/ec-public-key.json");
    EllipticCurveJwk key = (EllipticCurveJwk) adapter.adaptFromJson(json);

    Assert.assertEquals("P-521", key.getCrv());
    Assert.assertEquals(PublicKeyUseType.sig, key.getUse());
    Assert.assertEquals("bilbo.baggins@hobbiton.example", key.getKid());
    Assert.assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt")), key.getX());
    Assert.assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1")), key.getY());
    Assert.assertNull(key.getD());

    Assert.assertEquals(KeyType.EC, key.getKty());
    System.out.println("  key ec-public-key  " + key.getClass().getSimpleName());
    System.out.println(json);
    System.out.println(" to ");
    System.out.println(adapter.adaptToJson(key));
  }

  @Test
  public void testEcPrivateKey() throws Exception {
    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/ec-private-key.json");
    EllipticCurveJwk key = (EllipticCurveJwk) adapter.adaptFromJson(json);
    Assert.assertEquals("P-521", key.getCrv());
    Assert.assertEquals(PublicKeyUseType.sig, key.getUse());
    Assert.assertEquals("bilbo.baggins@hobbiton.example", key.getKid());
    Assert.assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt")), key.getX());
    Assert.assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1")), key.getY());
    Assert.assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt")), key.getD());

    EllipticCurveJwk keyReconverted = (EllipticCurveJwk) new JsonbUtility().unmarshal(new JsonbUtility().marshal(key), AbstractJwk.class);
    Assert.assertEquals(key, keyReconverted);

    Assert.assertEquals(KeyType.EC, key.getKty());
    System.out.println("  key ec-private-key  " + key.getClass().getSimpleName());
  }

  @Test
  public void testRsaPublicKey() throws Exception {
    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/rsa-public-key.json");
    RsaPublicJwk key = (RsaPublicJwk) adapter.adaptFromJson(json);
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O"
                                + "-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL"
                                + "-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe"
                                + "-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3"
                                + "-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw")), key
                 .getModulus());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AQAB")), key.getPublicExponent());
    assertEquals(PublicKeyUseType.sig, key.getUse());
    assertEquals("bilbo.baggins@hobbiton.example", key.getKid());

    RsaPublicJwk keyReconverted = (RsaPublicJwk) new JsonbUtility().unmarshal(new JsonbUtility().marshal(key), AbstractJwk.class);
    assertEquals(key, keyReconverted);

    Assert.assertEquals(KeyType.RSA, key.getKty());
    System.out.println("  key rsa-public-key  " + key.getClass().getSimpleName());
  }

  @Test
  public void testRsaPrivateKey() throws Exception {
    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/rsa-private-key.json");
    RsaPrivateJwk key = (RsaPrivateJwk) adapter.adaptFromJson(json);
    Assert.assertEquals(KeyType.RSA, key.getKty());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O"
                                + "-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL"
                                + "-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe"
                                + "-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3"
                                + "-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw")), key
                 .getModulus());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ"
                                + "-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA"
                                + "-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h"
                                + "-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ")
    ), key.getPrivateExponent());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AQAB")), key.getPublicExponent());
    assertEquals(PublicKeyUseType.sig, key.getUse());
    assertEquals("bilbo.baggins@hobbiton.example", key.getKid());

    RsaPrivateJwk keyReconverted = (RsaPrivateJwk) new JsonbUtility().unmarshal(new JsonbUtility().marshal(key), AbstractJwk.class);
    assertEquals(key, keyReconverted);

    System.out.println("  key rsa-private-key  " + key.getClass().getSimpleName());
  }

}
