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
import java.util.Random;
import java.util.UUID;
import org.ietf.test.DemoDto;
import org.junit.*;

/**
 *
 * @author Key Bridge
 */
public class JweUtilityTest {

  private DemoDto dto;

  private static LoremIpsum l = LoremIpsum.getInstance();
  private static Random r = new Random();

  private static KeyPair senderKeyPair;
  private static KeyPair recipientKeyPair;
  private static String sharedSecret;
  private static String senderKeyId;
  private static String recipientKeyId;

  public JweUtilityTest() {
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
    dto = new DemoDto(l.getWords(5, 10));
  }

  @After
  public void tearDown() {
  }

  @Test
  public void testEncryptAndDecryptKeyPair() throws Exception {
//    System.out.println("  Start with   " + dto);
    String jsonCompact = JweUtility.encrypt(dto, recipientKeyPair.getPublic(), recipientKeyId);
//    System.out.println("    jsonCompact " + jsonCompact);
//    System.out.println("    jsonCompact " + jsonCompact.length());
    DemoDto decrypted = JweUtility.decrypt(jsonCompact, DemoDto.class, recipientKeyPair.getPrivate());
//    System.out.println("  Decrypted as " + decrypted);
    Assert.assertEquals(dto, decrypted);
    System.out.println("testEncryptAndDecrypt KeyPair OK");
  }

  @Test
  public void testEncryptAndDecryptSharedSecret() throws Exception {
//    System.out.println("  Start with   " + dto);
    String jsonCompact = JweUtility.encrypt(dto, sharedSecret, recipientKeyId);
//    System.out.println("    jsonCompact " + jsonCompact);
//    System.out.println("    jsonCompact " + jsonCompact.length());
    DemoDto decrypted = JweUtility.decrypt(jsonCompact, DemoDto.class, sharedSecret);
//    System.out.println("  Decrypted as " + decrypted);
    Assert.assertEquals(dto, decrypted);
    System.out.println("testEncryptAndDecrypt SharedSecret OK");
  }

}
