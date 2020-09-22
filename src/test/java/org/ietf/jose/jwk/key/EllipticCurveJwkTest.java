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
package org.ietf.jose.jwk.key;

import java.math.BigInteger;
import org.ietf.TestFileReader;
import org.ietf.jose.jwk.PublicKeyUseType;
import org.ietf.jose.util.Base64Utility;
import org.ietf.jose.util.JsonbUtility;
import org.junit.*;

import static org.junit.Assert.assertEquals;

/**
 *
 * @author Key Bridge
 */
public class EllipticCurveJwkTest {

  private static JsonbUtility jsonb;

  public EllipticCurveJwkTest() {
  }

  @BeforeClass
  public static void setUpClass() {
    jsonb = new JsonbUtility();
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
  public void ecPublicKeyTest() throws Exception {
    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/ec-public-key.json");
    // marshal to object
    EllipticCurvePublicJwk ecKey = jsonb.unmarshal(json, EllipticCurvePublicJwk.class);
//    EllipticCurveJwk ecKey = (EllipticCurveJwk) adapter.adaptFromJson(json);

    assertEquals(EllipticCurveType.P_521, ecKey.getCrv());
    assertEquals(PublicKeyUseType.sig, ecKey.getUse());
    assertEquals("bilbo.baggins@hobbiton.example", ecKey.getKid());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt")), ecKey.getX());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1")), ecKey.getY());
//    assertNull(ecKey.getD());
//    System.out.println(jsonb.withFormatting(true).marshal(ecKey));

  }

  @Test
  public void ecPrivateKeyTest() {
    String json = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/ec-private-key.json");

    EllipticCurvePrivateJwk ecKey = new JsonbUtility().unmarshal(json, EllipticCurvePrivateJwk.class);

    assertEquals(EllipticCurveType.P_521, ecKey.getCrv());
    assertEquals(PublicKeyUseType.sig, ecKey.getUse());
    assertEquals("bilbo.baggins@hobbiton.example", ecKey.getKid());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt")), ecKey.getX());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1")), ecKey.getY());
    assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt")), ecKey.getD());

    EllipticCurvePrivateJwk keyReconverted = new JsonbUtility().unmarshal(new JsonbUtility().marshal(ecKey), EllipticCurvePrivateJwk.class);
    assertEquals(ecKey, keyReconverted);
  }
}
