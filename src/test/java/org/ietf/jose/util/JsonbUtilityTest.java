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
package org.ietf.jose.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import org.ietf.jose.jwe.JsonWebEncryption;
import org.ietf.jose.jwe.JweBuilder;
import org.junit.*;

import static org.junit.Assert.assertEquals;

/**
 *
 * @author Key Bridge
 */
public class JsonbUtilityTest {

  private static JsonbUtility jsonb;

  public JsonbUtilityTest() {
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
  public void jsonMarshalUnmarshal() throws NoSuchAlgorithmException, IOException, GeneralSecurityException {

    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); // throws NoSuchAlgorithmException
    generator.initialize(2048);
    KeyPair keyPair = generator.generateKeyPair();
    JsonWebEncryption original = JweBuilder.getInstance()
      .withBinaryPayload("somePayload".getBytes(StandardCharsets.UTF_8))
      .buildJweJsonFlattened(keyPair.getPublic(), "someKeyId"); // throws IOException, GeneralSecurityException

    String jsonText = jsonb.marshal(original);

    JsonWebEncryption unmarshalled = jsonb.unmarshal(jsonText, JsonWebEncryption.class);

    jsonb = jsonb.withFormatting(true);
    String jsonPretty = jsonb.marshal(original);
    System.out.println(jsonPretty);
    JsonWebEncryption unmarshalledFromPrettyJson = jsonb.unmarshal(jsonPretty, JsonWebEncryption.class);
    assertEquals(original, unmarshalled);
    assertEquals(original, unmarshalledFromPrettyJson);
  }

}
