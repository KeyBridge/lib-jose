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
import org.ietf.jose.jwk.key.EllipticCurvePrivateJwk;
import org.ietf.jose.jwk.key.EllipticCurvePublicJwk;
import org.ietf.jose.jwk.key.EllipticCurveType;
import org.ietf.jose.util.Base64Utility;
import org.ietf.jose.util.JsonbUtility;
import org.junit.*;

/**
 *
 * @author Key Bridge
 */
public class JsonbJwkDeserializerTest {

  private static JsonbUtility jsonb;

  public JsonbJwkDeserializerTest() {
  }

  @BeforeClass
  public static void setUpClass() {
    jsonb = new JsonbUtility();
//      .withDeserializers(new JsonbJwkDeserializer());

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
  public void testEllipticCurveJwk() {
    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/ec-public-key.json");

    EllipticCurvePublicJwk key = jsonb.unmarshal(json, EllipticCurvePublicJwk.class);
    Assert.assertEquals(EllipticCurveType.P_521, key.getCrv());
    Assert.assertEquals(PublicKeyUseType.sig, key.getUse());
    Assert.assertEquals("bilbo.baggins@hobbiton.example", key.getKid());
    Assert.assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt")), key.getX());
    Assert.assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1")), key.getY());
//    Assert.assertNull(key.getD());

    Assert.assertEquals(KeyType.EC, key.getKty());
    System.out.println("  key ec-public-key  " + key.getClass().getSimpleName());
//    System.out.println(json);    System.out.println(" to ");    System.out.println(jsonb.marshal(key));
  }

  @Test
  public void testEcPrivateKey() throws Exception {
    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/ec-private-key.json");
    EllipticCurvePrivateJwk key = jsonb.unmarshal(json, EllipticCurvePrivateJwk.class);
    Assert.assertEquals(EllipticCurveType.P_521, key.getCrv());
    Assert.assertEquals(PublicKeyUseType.sig, key.getUse());
    Assert.assertEquals("bilbo.baggins@hobbiton.example", key.getKid());
    Assert.assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt")), key.getX());
    Assert.assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1")), key.getY());
    Assert.assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt")), key.getD());

    EllipticCurvePrivateJwk keyReconverted = new JsonbUtility().unmarshal(new JsonbUtility().marshal(key), EllipticCurvePrivateJwk.class);
    Assert.assertEquals(key, keyReconverted);

    Assert.assertEquals(KeyType.EC, key.getKty());
    System.out.println("  key ec-private-key  " + key.getClass().getSimpleName());
  }

}
