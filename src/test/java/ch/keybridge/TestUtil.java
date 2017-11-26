package ch.keybridge;

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
}
