/*
 * Copyright 2018 Key Bridge. All rights reserved. Use is subject to license
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

import java.security.NoSuchAlgorithmException;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Key Bridge
 */
public class SecureRandomUtilityTest {

  private SecureRandomUtility sr;

  public SecureRandomUtilityTest() {
  }

  @Before
  public void setUp() {
    this.sr = new SecureRandomUtility();
  }

  @Test
  public void testGenerateBytes() throws NoSuchAlgorithmException {

    int numberOfBytes = 64;

    System.out.println("Generating 10 random byte sequences to confirm SecureRandom works on this JDK");
    for (int i = 0; i < 10; i++) {
      byte[] bytes = SecureRandomUtility.generateBytes(numberOfBytes);

      System.out.println("  " + bytesToHex(bytes));
    }

  }
  private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

  public static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for (int j = 0; j < bytes.length; j++) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }
}
