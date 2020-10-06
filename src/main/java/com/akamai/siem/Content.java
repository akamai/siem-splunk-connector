
package com.akamai.siem;


import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Content {

  @JsonProperty("access_token")
  private String accessToken;
  @JsonProperty("client_secret")
  private String clientSecret;
  @JsonProperty("client_token")
  private String clientToken;
  private Boolean disabled;
  private Object eaiAcl;
  private String host;
  @JsonProperty("host_resolved")
  private String hostResolved;
  private String hostname;
  private String index;
  @JsonProperty("initial_epoch_time")
  private Integer initialEpochTime;
  @JsonProperty("final_epoch_time")
  private Integer finalEpochTime;
  private String interval;
  private Integer limit;
  @JsonProperty("log_level")
  private String logLevel;
  @JsonProperty("security_configuration_id_s_")
  private String securityConfigurationids;
  private String sourcetype;
  private Map<String, Object> additionalProperties = new HashMap<String, Object>();

  public String getAccessToken() {
    return accessToken;
  }

  public void setAccessToken(String accessToken) {
    this.accessToken = accessToken;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  public void setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
  }

  public String getClientToken() {
    return clientToken;
  }

  public void setClientToken(String clientToken) {
    this.clientToken = clientToken;
  }

  public Boolean getDisabled() {
    return disabled;
  }

  public void setDisabled(Boolean disabled) {
    this.disabled = disabled;
  }

  public Object getEaiAcl() {
    return eaiAcl;
  }

  public void setEaiAcl(Object eaiAcl) {
    this.eaiAcl = eaiAcl;
  }

  public String getHost() {
    return host;
  }

  public void setHost(String host) {
    this.host = host;
  }

  public String getHostResolved() {
    return hostResolved;
  }

  public void setHostResolved(String hostResolved) {
    this.hostResolved = hostResolved;
  }

  public String getHostname() {
    return hostname;
  }

  public void setHostname(String hostname) {
    this.hostname = hostname;
  }

  public String getIndex() {
    return index;
  }

  public void setIndex(String index) {
    this.index = index;
  }

  public Integer getInitialEpochTime() {
    return initialEpochTime;
  }

  public void setInitialEpochTime(Integer initialEpochTime) {
    this.initialEpochTime = initialEpochTime;
  }

  public Integer getFinalEpochTime() {
    return finalEpochTime;
  }

  public void setFinalEpochTime(Integer finalEpochTime) {
    this.finalEpochTime = finalEpochTime;
  }

  public String getInterval() {
    return interval;
  }

  public void setInterval(String interval) {
    this.interval = interval;
  }

  public Integer getLimit() {
    return limit;
  }

  public void setLimit(Integer limit) {
    this.limit = limit;
  }

  public String getLogLevel() {
    return logLevel;
  }

  public void setLogLevel(String logLevel) {
    this.logLevel = logLevel;
  }

  public String getSecurityConfigurationIdS() {
    return securityConfigurationids;
  }

  public void setSecurityConfigurationIdS(String securityConfigurationIdS) {
    this.securityConfigurationids = securityConfigurationIdS;
  }

  public String getSourcetype() {
    return sourcetype;
  }

  public void setSourcetype(String sourcetype) {
    this.sourcetype = sourcetype;
  }

  public Map<String, Object> getAdditionalProperties() {
    return this.additionalProperties;
  }

  public void setAdditionalProperty(String name, Object value) {
    this.additionalProperties.put(name, value);
  }

}
