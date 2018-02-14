package ch.keybridge.jose.util;

import java.nio.charset.Charset;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * A Base64 and Base64URL encoding utility with defaults consistent with the JOSE family of formats.
 */
public class Base64Utility {
  /**
   * JOSE family JSON objects require BASE64(URL)-encoded string to be unpadded.
   */
  private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();
  public static final Charset DEFAULT_CHARSET = UTF_8;

  /**
   * Convert any string to base64Url
   *
   * @param text any text
   * @return base64url-encoded string
   */
  public static String toBase64Url(String text) {
    return URL_ENCODER.encodeToString(text.getBytes(DEFAULT_CHARSET));
  }

  /**
   * Convert a byte blob into base64Url
   *
   * @param bytes some byte array
   * @return base64url-encoded string
   */
  public static String toBase64Url(byte[] bytes) {
    return URL_ENCODER.encodeToString(bytes);
  }

  /**
   * Decode a base64Url-encoded string into a byte array
   *
   * @param text base64url-encoded string
   * @return decoded bytes
   */
  public static byte[] fromBase64Url(String text) {
    return URL_DECODER.decode(text);
  }

  /**
   * Decode a base64Url-encoded string into a string
   *
   * @param base64encoded base64url-encoded string
   * @return decoded string
   */
  public static String fromBase64UrlToString(String base64encoded) {
    return new String(fromBase64Url(base64encoded), DEFAULT_CHARSET);
  }
}
