package com.akamai.siem;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AttackData {

  private String rules;
  private String ruleVersions;
  private String ruleMessages;
  private String ruleTags;
  private String ruleData;
  private String ruleSelectors;
  private String ruleActions;

  public String apiId;
  public String apiKey;
  public String clientReputation;
  public String slowPostAction;
  public String slowPostRate;


  public void setRules(String rules) {
    this.rules = rules;
  }

  public void setRuleVersions(String ruleVersions) {
    this.ruleVersions = ruleVersions;
  }

  public void setRuleMessages(String ruleMessages) {
    this.ruleMessages = ruleMessages;
  }

  public void setRuleTags(String ruleTags) {
    this.ruleTags = ruleTags;
  }

  public void setRuleData(String ruleData) {
    this.ruleData = ruleData;
  }

  public void setRuleSelectors(String ruleSelectors) {
    this.ruleSelectors = ruleSelectors;
  }

  public void setRuleActions(String ruleActions) {
    this.ruleActions = ruleActions;
  }

  public String configId;
  public String policyId;
  public String clientIP;

  @JsonProperty(value = "rules", access = JsonProperty.Access.READ_ONLY)
  public List<Rule> rulez;

  public String getConfigId() {
    return configId;
  }

  public void setConfigId(String configId) {
    this.configId = configId;
  }

  public String getPolicyId() {
    return policyId;
  }

  public void setPolicyId(String policyId) {
    this.policyId = policyId;
  }

  public String getClientIP() {
    return clientIP;
  }

  public void setClientIP(String clientIP) {
    this.clientIP = clientIP;
  }


  public List<Rule> getRulez() {
    return rulez;
  }

  public void setRulez(List<Rule> rulez) {
    this.rulez = rulez;
  }

  public String getApiId() {
    return apiId;
  }

  public void setApiId(String apiId) {
    this.apiId = apiId;
  }

  public String getApiKey() {
    return apiKey;
  }

  public void setApiKey(String apiKey) {
    this.apiKey = apiKey;
  }

  public String getClientReputation() {
    return clientReputation;
  }

  public void setClientReputation(String clientReputation) {
    this.clientReputation = clientReputation;
  }

  public String getSlowPostAction() {
    return slowPostAction;
  }

  public void setSlowPostAction(String slowPostAction) {
    this.slowPostAction = slowPostAction;
  }

  public String getSlowPostRate() {
    return slowPostRate;
  }

  public void setSlowPostRate(String slowPostRate) {
    this.slowPostRate = slowPostRate;
  }

  public void processRaw() throws UnsupportedEncodingException {

    List<String> rules = decode(this.rules);
    List<String> ruleVersions = decode(this.ruleVersions);
    List<String> ruleMessages = decode(this.ruleMessages);
    List<String> ruleTags = decode(this.ruleTags);
    List<String> ruleData = decode(this.ruleData);
    List<String> ruleSelectors = decode(this.ruleSelectors);
    List<String> ruleActions = decode(this.ruleActions);

    int maxSize = Stream.of(rules.size(), ruleVersions.size(), ruleMessages.size(), ruleTags.size(), ruleData.size(),
        ruleSelectors.size(), ruleActions.size()).max(Integer::compareTo).get();

    if (rulez == null) {
      rulez = new ArrayList<Rule>();
    }

    for (int i = 0; i < maxSize; i++) {

      Rule newRule =
          new Rule(((i < rules.size()) ? rules.get(i) : ""), ((i < ruleVersions.size()) ? ruleVersions.get(i) : ""),
              ((i < ruleMessages.size()) ? ruleMessages.get(i) : ""), ((i < ruleTags.size()) ? ruleTags.get(i) : ""),
              ((i < ruleData.size()) ? ruleData.get(i) : ""), ((i < ruleSelectors.size()) ? ruleSelectors.get(i) : ""),
              ((i < ruleActions.size()) ? ruleActions.get(i) : ""));
      rulez.add(newRule);
    }

  }


  /*
   * URL decode Tokenize on ; Base64 decode array of results from above
   */
  private List<String> decode(String value) throws UnsupportedEncodingException {
    ArrayList<String> retVal = new ArrayList<String>();
    String urlDecodeValue = value;
    urlDecodeValue = java.net.URLDecoder.decode(value, "UTF-8");
    String[] tokenized = urlDecodeValue.split(";");
    for (int i = 0; i < tokenized.length; i++) {
      String[] detectSpaces = tokenized[i].split(" ");
      StringBuilder sb = new StringBuilder();
      for (String ss : detectSpaces) {
        if (sb.length() > 0) {
          sb.append(" ");
        }
        sb.append(new String(org.apache.commons.codec.binary.Base64.decodeBase64(ss), StandardCharsets.UTF_8));
      }
      retVal.add(sb.toString());
    }
    return (retVal);
  }
}
