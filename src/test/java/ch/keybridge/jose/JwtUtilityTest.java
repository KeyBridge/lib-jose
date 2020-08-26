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

import com.thedeanda.lorem.LoremIpsum;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Random;
import java.util.UUID;
import org.ietf.jose.jwt.JwtClaims;
import org.junit.*;

/**
 *
 * @author Key Bridge
 */
public class JwtUtilityTest {

  private JwtClaims claims;

  private static LoremIpsum l = LoremIpsum.getInstance();
  private static Random r = new Random();

  private static KeyPair senderKeyPair;
  private static KeyPair recipientKeyPair;
  private static String sharedSecret;
  private static String senderKeyId;
  private static String recipientKeyId;

  public JwtUtilityTest() {
  }

  @BeforeClass
  public static void setUpClass() throws NoSuchAlgorithmException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    senderKeyPair = generator.generateKeyPair();
    senderKeyId = UUID.randomUUID().toString();
    recipientKeyPair = generator.generateKeyPair();
    recipientKeyId = UUID.randomUUID().toString();
    sharedSecret = l.getWords(3, 5);
  }

  @AfterClass
  public static void tearDownClass() {
  }

  @Before
  public void setUp() {
    claims = new JwtClaims()
      .withIssuer(senderKeyId)
      .withAudience(l.getUrl())
      .withSubject(recipientKeyId)
      .withDuration(Duration.ofDays(r.nextInt(30)));
  }

  @After
  public void tearDown() {
  }

  @Test
  public void testSignAndVerifyKeyPair() throws Exception {
//    System.out.println("  Start with   " + claims);
    String jsonCompact = JwtUtility.sign(claims, senderKeyPair.getPrivate(), senderKeyId);
//    System.out.println("    jsonCompact " + jsonCompact);
//    System.out.println("    jsonCompact " + jsonCompact.length());
    JwtClaims recovered = JwtUtility.verifySignature(jsonCompact, senderKeyPair.getPublic());
//    System.out.println("  Verified as  " + recovered);
    Assert.assertEquals(claims, recovered);
    System.out.println("testSignAndVerify KeyPair OK");

  }

  @Test
  public void testSignAndVerifySharedSecret() throws Exception {
//    System.out.println("  Start with   " + claims);
    String jsonCompact = JwtUtility.sign(claims, sharedSecret, senderKeyId);
//    System.out.println("    jsonCompact " + jsonCompact);
//    System.out.println("    jsonCompact " + jsonCompact.length());
    JwtClaims recovered = JwtUtility.verifySignature(jsonCompact, sharedSecret);
//    System.out.println("  Verified as  " + recovered);
    Assert.assertEquals(claims, recovered);
    System.out.println("testSignAndVerify SharedSecret OK");
  }

  @Test
  public void testEncryptAndDecryptKeyPair() throws Exception {
//    System.out.println("  Start with   " + claims);
    String jsonCompact = JwtUtility.encrypt(claims, recipientKeyPair.getPublic(), recipientKeyId);
//    System.out.println("    jsonCompact " + jsonCompact);
//    System.out.println("    jsonCompact " + jsonCompact.length());
    JwtClaims recovered = JwtUtility.decrypt(jsonCompact, recipientKeyPair.getPrivate());
//    System.out.println("  Verified as  " + recovered);
    Assert.assertEquals(claims, recovered);
    System.out.println("testEncryptAndDecrypt KeyPair OK");
  }

  @Test
  public void testEncryptAndDecryptSharedSecret() throws Exception {
//    System.out.println("  Start with   " + claims);
    String jsonCompact = JwtUtility.encrypt(claims, sharedSecret, recipientKeyId);
//    System.out.println("    jsonCompact " + jsonCompact);
//    System.out.println("    jsonCompact " + jsonCompact.length());
    JwtClaims recovered = JwtUtility.decrypt(jsonCompact, sharedSecret);
//    System.out.println("  Verified as  " + recovered);
    Assert.assertEquals(claims, recovered);
    System.out.println("testEncryptAndDecrypt SharedSecret OK");
  }

  @Test
  public void testSignEncryptAndDecryptVerifyKeyPair() throws Exception {
//    System.out.println("  Start with   " + claims);
    String jsonCompact = JwtUtility.signAndEncrypt(claims, senderKeyPair.getPrivate(), recipientKeyPair.getPublic(), senderKeyId, recipientKeyId);
    System.out.println("    jsonCompact " + jsonCompact);
    System.out.println("    jsonCompact " + jsonCompact.length());
    JwtClaims recovered = JwtUtility.decryptAndVerifySignature(jsonCompact, recipientKeyPair.getPrivate(), senderKeyPair.getPublic());
//    System.out.println("  Verified as  " + recovered);
    Assert.assertEquals(claims, recovered);
    System.out.println("testSignEncryptAndDecryptVerify KeyPair OK");
  }

  @Test
  public void testSignEncryptAndDecryptVerifySharedSecret() throws Exception {

    System.out.println("  Start with   " + claims);
    String jsonCompact = JwtUtility.signAndEncrypt(claims, sharedSecret, recipientKeyId);
//    System.out.println("    jsonCompact " + jsonCompact);
//    System.out.println("    jsonCompact " + jsonCompact.length());
    JwtClaims recovered = JwtUtility.decryptAndVerifySignature(jsonCompact, sharedSecret);
    System.out.println("  Verified as  " + recovered);
    Assert.assertEquals(claims, recovered);
    System.out.println("testSignEncryptAndDecryptVerify KeyPair OK");

    wrapText(jsonCompact);

  }

  @Test
  public void testSignEncryptAndDecryptVerifySharedSecretFormatted() throws Exception {
    System.out.println("  Start with   " + claims);
    String jsonCompact = JwtUtility.signAndEncrypt(claims, sharedSecret, recipientKeyId);
    String jsonCompactFormatted = JwtUtility.format(jsonCompact);
    String jsonCompactUnFormatted = JwtUtility.unformat(jsonCompactFormatted);
    JwtClaims recovered = JwtUtility.decryptAndVerifySignature(jsonCompactUnFormatted, sharedSecret);
    System.out.println("  Verified as  " + recovered);
    Assert.assertEquals(claims, recovered);
    System.out.println("testSignEncryptAndDecryptVerify formatted KeyPair OK");

    wrapText(jsonCompact);

  }

  private void wrapText(String text) {
    StringBuilder sb = new StringBuilder(text);

    int lineWidth = 80;
    int i = lineWidth;
    while (i < sb.length()) {
      sb.insert(i, "\n");
      i += lineWidth;
    }
    System.out.println("---");
    System.out.println(sb.toString());
    System.out.println("---");
  }

}
