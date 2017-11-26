package ch.keybridge.jose.util;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class EncodingUtility {
  public static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
  public static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();
  public static final Charset UTF8 = StandardCharsets.UTF_8;
  public static final Charset ASCII = StandardCharsets.US_ASCII;

  public static byte[] getUtf8Bytes(String text) {
    return text == null ? new byte[0] : text.getBytes(UTF8);
  }

  public static String encodeBase64Url(String text) {
    return URL_ENCODER.encodeToString(text.getBytes(UTF8));
  }

  public static String encodeBase64Url(byte[] bytes) {
    return URL_ENCODER.encodeToString(bytes);
  }

  public static byte[] encodeBase64UrlAscii(String text) {
    return encodeBase64Url(text).getBytes(ASCII);
  }

  public static byte[] decodeBase64Url(String text) {
    return URL_DECODER.decode(text);
  }

  public static String decodeBase64UrlToString(String base64encoded) {
    return new String(decodeBase64Url(base64encoded), UTF8);
  }
}
