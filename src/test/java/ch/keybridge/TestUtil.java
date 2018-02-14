package ch.keybridge;

import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

public class TestUtil {

  public static byte[] convertUnsignedIntsToBytes(int[] unsignedBytes) {
    byte[] bytes = new byte[unsignedBytes.length];
    for (int i = 0; i < unsignedBytes.length; i++) {
      final int value = unsignedBytes[i];
//      bytes[i] = (byte) (value < 127 ? value : value - 256);
      bytes[i] = (byte)(value & 0xFF);
    }
    return bytes;
  }
  public static int[] toUnsignedInt(byte[] bytes) {
    int[] integers = new int[bytes.length];
    for (int i = 0; i < integers.length; i++) {
      integers[i] = Byte.toUnsignedInt(bytes[i]);
    }
    return integers;
  }

  public static String createRandomString(int length) {
    StringBuilder b = new StringBuilder();
    ThreadLocalRandom r = ThreadLocalRandom.current();
    while (b.length() < length) {
      b.append((char) (r.nextInt(26) + 'a'));
    }
    return b.toString();
  }

  public static String getAlteredString(String original) {
    ThreadLocalRandom r = ThreadLocalRandom.current();
    char[] characters = original.toCharArray();
    int idx = r.nextInt(characters.length);
    char newChar = characters[idx];
    while (newChar == characters[idx]) {
      newChar = (char) ((characters[idx] + r.nextInt()) % 26 + 'a');
    }
    characters[idx] = newChar;
    return new String(characters);
  }

  public static byte[] getAlteredBytes(byte[] original) {
    int idx = ThreadLocalRandom.current().nextInt(original.length);
    byte[] copy = Arrays.copyOf(original, original.length);
    copy[idx] = (byte) (copy[idx] + 1);
    return copy;
  }
}
