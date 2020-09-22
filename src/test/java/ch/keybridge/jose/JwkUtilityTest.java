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
package ch.keybridge.jose;

import ch.keybridge.cryptography.KeyPairFactory;
import ch.keybridge.cryptography.names.KeyPairGeneratorAlgorithm;
import java.security.KeyPair;
import java.util.Random;
import java.util.UUID;
import org.ietf.jose.jwk.JwkSet;
import org.ietf.jose.util.JsonbUtility;
import org.junit.*;

/**
 *
 * @author Key Bridge
 */
public class JwkUtilityTest {

  private Random r = new Random();
  private static JsonbUtility jsonb;

  public JwkUtilityTest() {
  }

  @BeforeClass
  public static void setUpClass() {
    jsonb = new JsonbUtility().withFormatting(true);

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
  public void testSomeMethod() throws Exception {

    JwkUtility.SetBuilder builder = JwkUtility.getSetBuilder();

    for (int i = 0; i < r.nextInt(10); i++) {
      KeyPair kp = KeyPairFactory.generate(KeyPairGeneratorAlgorithm.RSA);

      builder.withKeyPair(kp, UUID.randomUUID().toString());

    }

    JwkSet jwkSet = builder.build();

    System.out.println(jsonb.marshal(jwkSet));

  }

}
