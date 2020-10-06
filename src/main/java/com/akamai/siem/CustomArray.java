package com.akamai.siem;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;



public class CustomArray {
  @JsonIgnore
  private String customKey;
  @JsonIgnore
  private List<String> customValue;

  public String getCustomKey() {
    return customKey;
  }

  public void setCustomKey(String customKey) {
    this.customKey = customKey;
  }

  public List<String> getCustomValue() {
    return customValue;
  }

  public void setCustomValue(List<String> customValue) {
    this.customValue = customValue;
  }

  @JsonAnySetter
  public void anySetter(String key, List<String> value) {
    customKey = key;
    customValue = value;
  }

  @JsonAnyGetter
  public Map<String, List<String>> anyGetter() {
    Map<String, List<String>> retVal = new HashMap<>();
    retVal.put(customKey, customValue);
    return (retVal);
  }

}


