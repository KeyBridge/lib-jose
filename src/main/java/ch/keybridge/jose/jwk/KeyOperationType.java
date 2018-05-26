package ch.keybridge.jose.jwk;

public enum KeyOperationType {
  SIGN("sign"),
  VERIFY("verify"),
  ENCRYPT("encrypt"),
  DECRYPT("decrypt"),
  WRAP_KEY("wrapKey"),
  UNWRAP_KEY("unwrapKey"),
  DERIVE_KEY("deriveKey"),
  DERIVE_BITS("deriveBits");

  private final String value;

  KeyOperationType(String value) {
    this.value = value;
  }

  public String getValue() {
    return value;
  }
}
