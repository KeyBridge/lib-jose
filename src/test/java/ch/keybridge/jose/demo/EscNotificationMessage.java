package ch.keybridge.jose.demo;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.Serializable;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class EscNotificationMessage implements Serializable {
  /**
   * The DPA unique identifier.
   */
  @XmlElement(required = true)
  private String dpaId;
  /**
   * Name of the DPA
   */
  private String name;
  /**
   * Description of the DPA
   */
  private String description;
  /**
   * The DPA-Channel (DPAC) state machine status.
   * <p>
   * TRUE indicates the DPAC is ACTIVE and must be protected. FALSE indicates the DPAC is INACTIVE and may be used
   * for spectrum operations.
   */
  @XmlElement(required = true)
  private boolean active;
  /**
   * The CBRS channel name.
   */
  @XmlElement(required = true)
  private String channelName;
  /**
   * Lower frequency bound for this channel (MHz)
   */
  @XmlElement(required = true)
  private Integer frequencyMin;
  /**
   * Upper frequency bound for this channel (MHz)
   */
  @XmlElement(required = true)
  private Integer frequencyMax;

  public String getDpaId() {
    return dpaId;
  }

  public void setDpaId(String dpaId) {
    this.dpaId = dpaId;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getDescription() {
    return description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  public boolean isActive() {
    return active;
  }

  public void setActive(boolean active) {
    this.active = active;
  }

  public String getChannelName() {
    return channelName;
  }

  public void setChannelName(String channelName) {
    this.channelName = channelName;
  }

  public Integer getFrequencyMin() {
    return frequencyMin;
  }

  public void setFrequencyMin(Integer frequencyMin) {
    this.frequencyMin = frequencyMin;
  }

  public Integer getFrequencyMax() {
    return frequencyMax;
  }

  public void setFrequencyMax(Integer frequencyMax) {
    this.frequencyMax = frequencyMax;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    EscNotificationMessage that = (EscNotificationMessage) o;

    if (active != that.active) return false;
    if (dpaId != null ? !dpaId.equals(that.dpaId) : that.dpaId != null) return false;
    if (name != null ? !name.equals(that.name) : that.name != null) return false;
    if (description != null ? !description.equals(that.description) : that.description != null) return false;
    if (channelName != null ? !channelName.equals(that.channelName) : that.channelName != null) return false;
    if (frequencyMin != null ? !frequencyMin.equals(that.frequencyMin) : that.frequencyMin != null) return false;
    return frequencyMax != null ? frequencyMax.equals(that.frequencyMax) : that.frequencyMax == null;
  }

  @Override
  public int hashCode() {
    int result = dpaId != null ? dpaId.hashCode() : 0;
    result = 31 * result + (name != null ? name.hashCode() : 0);
    result = 31 * result + (description != null ? description.hashCode() : 0);
    result = 31 * result + (active ? 1 : 0);
    result = 31 * result + (channelName != null ? channelName.hashCode() : 0);
    result = 31 * result + (frequencyMin != null ? frequencyMin.hashCode() : 0);
    result = 31 * result + (frequencyMax != null ? frequencyMax.hashCode() : 0);
    return result;
  }

  @Override
  public String toString() {
    return "EscNotificationMessage{" +
        "dpaId='" + dpaId + '\'' +
        ", name='" + name + '\'' +
        ", description='" + description + '\'' +
        ", active=" + active +
        ", channelName='" + channelName + '\'' +
        ", frequencyMin=" + frequencyMin +
        ", frequencyMax=" + frequencyMax +
        '}';
  }
}
