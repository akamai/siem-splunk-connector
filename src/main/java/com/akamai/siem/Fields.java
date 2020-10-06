
package com.akamai.siem;

import java.util.List;

public class Fields {

  private List<String> required = null;
  private List<String> optional = null;
  private List<Object> wildcard = null;

  public List<String> getRequired() {
    return required;
  }

  public void setRequired(List<String> required) {
    this.required = required;
  }

  public List<String> getOptional() {
    return optional;
  }

  public void setOptional(List<String> optional) {
    this.optional = optional;
  }

  public List<Object> getWildcard() {
    return wildcard;
  }

  public void setWildcard(List<Object> wildcard) {
    this.wildcard = wildcard;
  }

}
