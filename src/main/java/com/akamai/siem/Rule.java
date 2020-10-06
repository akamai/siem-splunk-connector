package com.akamai.siem;

public class Rule {

  public Rule() {

  }

  public Rule(String rules, String ruleVersions, String ruleMessages, String ruleTags, String ruleData,
      String ruleSelectors, String ruleActions) {
    action = ruleActions;
    data = ruleData;
    message = ruleMessages;
    selector = ruleSelectors;
    tag = ruleTags;
    version = ruleVersions;
    id = rules;
  }

  private String data;
  private String action;
  private String selector;
  private String tag;
  private String id;
  private String message;
  private String version;

  public String getData() {
    return data;
  }

  public void setData(String data) {
    this.data = data;
  }

  public String getAction() {
    return action;
  }

  public void setAction(String action) {
    this.action = action;
  }

  public String getSelector() {
    return selector;
  }

  public void setSelector(String selector) {
    this.selector = selector;
  }

  public String getTag() {
    return tag;
  }

  public void setTag(String tag) {
    this.tag = tag;
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getMessage() {
    return message;
  }

  public void setMessage(String message) {
    this.message = message;
  }

  public String getVersion() {
    return version;
  }

  public void setVersion(String version) {
    this.version = version;
  }

}
