package ch.keybridge.jose.jwe.encryption;

/**
 * @author Andrius Druzinis-Vitkus
 * @since 0.0.1 created 03/01/2018
 */
public class EncryptionResult {

  private final byte[] iv;
  private final byte[] aad;
  private final byte[] ciphertext;
  private final byte[] authTag;

  public EncryptionResult(byte[] iv, byte[] aad, byte[] ciphertext, byte[] authTag) {
    this.iv = iv;
    this.aad = aad;
    this.ciphertext = ciphertext;
    this.authTag = authTag;
  }

  public byte[] getIv() {
    return iv;
  }

  public byte[] getAad() {
    return aad;
  }

  public byte[] getCiphertext() {
    return ciphertext;
  }

  public byte[] getAuthTag() {
    return authTag;
  }
}
