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
package org.ietf.jose.jws;

import java.io.IOException;
import java.util.Arrays;
import org.ietf.TestFileReader;
import org.ietf.jose.util.Base64Utility;
import org.ietf.jose.util.JsonbUtility;
import org.junit.*;

/**
 *
 * @author Key Bridge
 */
public class JsonWebSignatureTest {

  public JsonWebSignatureTest() {
  }

  @BeforeClass
  public static void setUpClass() {
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
  public void testSomeMethod() throws IOException {

    String json = TestFileReader.getTestCase("/rfc7515/jws-example.json");

    System.out.println("json " + json);

    JsonWebSignature jws = new JsonbUtility().unmarshal(json, JsonWebSignature.class);

    System.out.println("unmarshal OK " + jws);
//    JsonWebSignature jws = JsonWebSignature.fromJson(json); // throws IOException
  }

  @Test
  public void testDecode() {
    String payload = "InNhbXBsZSB0ZXh0IHRvIHNpZ24gYW5kIGVuY3J5cHQi";
    byte[] bytes = Base64Utility.fromBase64Url(payload);
    System.out.println("bytes: " + Arrays.toString(bytes));
  }
}
