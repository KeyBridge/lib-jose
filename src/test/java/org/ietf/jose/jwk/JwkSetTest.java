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
package org.ietf.jose.jwk;

import org.ietf.TestFileReader;
import org.ietf.jose.jwk.key.AbstractJwk;
import org.ietf.jose.jwk.key.EllipticCurveJwk;
import org.ietf.jose.jwk.key.RsaPublicJwk;
import org.ietf.jose.util.JsonbUtility;
import org.junit.*;

/**
 *
 * @author Key Bridge
 */
public class JwkSetTest {

  private static JsonbUtility jsonb;

  public JwkSetTest() {
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

//  @Test
  public void testMarshalJwkSet() {

    String ecPublic = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/ec-public-key.json");
    String rsaPublic = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/rsa-public-key.json");

    JwkSet jwkSet = new JwkSet();

    jwkSet.addKey(jsonb.unmarshal(ecPublic, EllipticCurveJwk.class));
    jwkSet.addKey(jsonb.unmarshal(rsaPublic, RsaPublicJwk.class));

    String json = new JsonbUtility().withFormatting(true).marshal(jwkSet);
    System.out.println("\n\n DEBUG JwkSet");
    System.out.println(json);
    System.out.println("\n\n DEBUG JwkSet");

    JwkSet setRecovered = new JsonbUtility().unmarshal(json, JwkSet.class);

    for (AbstractJwk key : setRecovered.getKeys()) {
      System.out.println("  " + key);
//      System.out.println(new JsonbUtility().withFormatting(true).marshal(key));
    }
  }

//  @Test
  public void testJwkSetRoundTrip() throws Exception {
    String ecPublic = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/ec-public-key.json");
    String rsaPublic = TestFileReader.getTestCase("/rfc7520/section3-jwk-examples/rsa-public-key.json");

    JwkSet jwkSet = new JwkSet();

    jwkSet.addKey(jsonb.unmarshal(ecPublic, EllipticCurveJwk.class));
    jwkSet.addKey(jsonb.unmarshal(rsaPublic, RsaPublicJwk.class));

    System.out.println(" jwkset has " + jwkSet.getKeys().size() + " entries ");
    String json = new JsonbUtility().withFormatting(true).marshal(jwkSet);
    System.out.println("\n\n DEBUG JwkSet OUT");
    System.out.println(json);
    System.out.println("\n\n DEBUG JwkSet");

    JwkSet setRecovered = new JsonbUtility().unmarshal(json, JwkSet.class);

    for (AbstractJwk key : setRecovered.getKeys()) {
      System.out.println("  setRecovered  " + key);
//      System.out.println(new JsonbUtility().withFormatting(true).marshal(key));
    }

  }

  @Test
  public void testJwkSet() {
    String json = TestFileReader.getTestCase("/rfc7517/appendix-a/public-keys.json");

    System.out.println(json);

    JwkSet jwkSet = jsonb.unmarshal(json, JwkSet.class);

    System.out.println(" read " + jwkSet.getKeys().size() + "  keys ");

    System.out.println(jsonb.withFormatting(true).marshal(jwkSet));

//    JsonbConfig jsonbConfig = new JsonbConfig()
//      .withBinaryDataStrategy(BinaryDataStrategy.BASE_64)
//      .withPropertyVisibilityStrategy(new JsonbPropertyVisibilityStrategy())
//      .withAdapters(new JsonbBigIntegerBase64UrlAdapter())
//      .withAdapters(new JsonbByteArrayBase64UrlAdapter());
//    Jsonb jsonb = JsonbBuilder.create(jsonbConfig);
//    JwkSet jwkSet = new JsonbUtility().unmarshal(json, JwkSet.class);
//    System.out.println("  set public-keys " + jwkSet.getKeys().size());
//    for (AbstractJwk key : jwkSet.getKeys()) {
//      System.out.println(" entry " + key);
//    }
//    Assert.assertEquals(2, jwkSet.getKeys().size());
//    Assert.assertTrue(jwkSet.getKeys().get(0) instanceof EllipticCurveJwk);
//    EllipticCurveJwk ecKey = (EllipticCurveJwk) jwkSet.getKeys().get(0);
//    Assert.assertEquals("P-256", ecKey.getCrv());
//    Assert.assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")), ecKey.getX());
//    Assert.assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")), ecKey.getY());
//    Assert.assertEquals(PublicKeyUseType.enc, ecKey.getUse());
//    Assert.assertEquals("1", ecKey.getKid());
//
//    Assert.assertTrue(jwkSet.getKeys().get(1) instanceof RsaPrivateJwk);
//
//    RsaPrivateJwk rsaKey = (RsaPrivateJwk) jwkSet.getKeys().get(1);
//    Assert.assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")), rsaKey.getModulus());
//    Assert.assertEquals(new BigInteger(1, Base64Utility.fromBase64Url("AQAB")), rsaKey.getPublicExponent());
//    Assert.assertEquals("RS256", rsaKey.getAlg());
//    Assert.assertEquals("2011-04-29", rsaKey.getKid());
//
//    JwkSet reconverted = new JsonbUtility().unmarshal(new JsonbUtility().marshal(jwkSet), JwkSet.class);
//    Assert.assertEquals(jwkSet, reconverted);
  }
}
