package com.akamai.siem;

import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;



public class Custom {

  public String getCustomKey() {
    return customKey;
  }

  public void setCustomKey(String customKey) {
    this.customKey = customKey;
  }

  public String getCustomValue() {
    return customValue;
  }

  public void setCustomValue(String customValue) {
    this.customValue = customValue;
  }

  @JsonIgnore
  private String customKey;
  @JsonIgnore
  private String customValue;

  @JsonAnySetter
  public void anySetter(String key, String value) {
    customKey = key;
    customValue = value;
  }

  @JsonAnyGetter
  public Map<String, String> anyGetter() {
    Map<String, String> retVal = new HashMap<>();
    retVal.put(customKey, customValue);
    return (retVal);
  }
}


