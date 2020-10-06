
package com.akamai.siem;

import java.util.List;

public class InputStanza {

  private Links links;
  private String origin;
  private String updated;
  private Generator generator;
  private List<Entry> entry = null;
  private Paging paging;
  private List<Object> messages = null;

  public Links getLinks() {
    return links;
  }

  public void setLinks(Links links) {
    this.links = links;
  }

  public String getOrigin() {
    return origin;
  }

  public void setOrigin(String origin) {
    this.origin = origin;
  }

  public String getUpdated() {
    return updated;
  }

  public void setUpdated(String updated) {
    this.updated = updated;
  }

  public Generator getGenerator() {
    return generator;
  }

  public void setGenerator(Generator generator) {
    this.generator = generator;
  }

  public List<Entry> getEntry() {
    return entry;
  }

  public void setEntry(List<Entry> entry) {
    this.entry = entry;
  }

  public Paging getPaging() {
    return paging;
  }

  public void setPaging(Paging paging) {
    this.paging = paging;
  }

  public List<Object> getMessages() {
    return messages;
  }

  public void setMessages(List<Object> messages) {
    this.messages = messages;
  }

}
