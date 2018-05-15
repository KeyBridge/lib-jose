package ch.keybridge.jose.demo;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.Serializable;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SasRegistrationRequest implements Serializable {
  /**
   * The URL where the ESC sends POST request containing all updates. The URL must be a fully-qualified URL of the
   * REST endpoint of the SAS. The SAS must have a HTTP listener at this URL active and available at the time of
   * registration. The listener should be listening at all times and should be highavailability. Must support HTTPS
   * and port 443 must be open. For example: https://client.com/sas/notify
   */
  @XmlElement(required = true)
  private String url;
  /**
   * The Internet Protocol (IPv4) address of the client server
   */
  @XmlElement(required = true)
  private String inet4Address;
  /**
   * The Internet Protocol (IPv6) address of the client server
   */
  private String inet6Address;
  /**
   * The hardware address (usually ethernet MAC) of the client server
   */
  private String hardwareAddress;
  /**
   * The host operating system name. Examples: Linux, MacOS, Windows, Android, etc.
   */
  private String os;

  public String getUrl() {
    return url;
  }

  public void setUrl(String url) {
    this.url = url;
  }

  public String getInet4Address() {
    return inet4Address;
  }

  public void setInet4Address(String inet4Address) {
    this.inet4Address = inet4Address;
  }

  public String getInet6Address() {
    return inet6Address;
  }

  public void setInet6Address(String inet6Address) {
    this.inet6Address = inet6Address;
  }

  public String getHardwareAddress() {
    return hardwareAddress;
  }

  public void setHardwareAddress(String hardwareAddress) {
    this.hardwareAddress = hardwareAddress;
  }

  public String getOs() {
    return os;
  }

  public void setOs(String os) {
    this.os = os;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    SasRegistrationRequest that = (SasRegistrationRequest) o;

    if (url != null ? !url.equals(that.url) : that.url != null) return false;
    if (inet4Address != null ? !inet4Address.equals(that.inet4Address) : that.inet4Address != null) return false;
    if (inet6Address != null ? !inet6Address.equals(that.inet6Address) : that.inet6Address != null) return false;
    if (hardwareAddress != null ? !hardwareAddress.equals(that.hardwareAddress) : that.hardwareAddress != null)
      return false;
    return os != null ? os.equals(that.os) : that.os == null;
  }

  @Override
  public int hashCode() {
    int result = url != null ? url.hashCode() : 0;
    result = 31 * result + (inet4Address != null ? inet4Address.hashCode() : 0);
    result = 31 * result + (inet6Address != null ? inet6Address.hashCode() : 0);
    result = 31 * result + (hardwareAddress != null ? hardwareAddress.hashCode() : 0);
    result = 31 * result + (os != null ? os.hashCode() : 0);
    return result;
  }

  @Override
  public String toString() {
    return "SasRegistrationRequest{" +
        "url='" + url + '\'' +
        ", inet4Address='" + inet4Address + '\'' +
        ", inet6Address='" + inet6Address + '\'' +
        ", hardwareAddress='" + hardwareAddress + '\'' +
        ", os='" + os + '\'' +
        '}';
  }
}
