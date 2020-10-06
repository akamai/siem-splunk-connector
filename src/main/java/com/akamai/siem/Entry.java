
package com.akamai.siem;

public class Entry {

  private String name;
  private String id;
  private String updated;
  private Links_ links;
  private String author;
  private Acl acl;
  private Fields fields;
  private Content content;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getUpdated() {
    return updated;
  }

  public void setUpdated(String updated) {
    this.updated = updated;
  }

  public Links_ getLinks() {
    return links;
  }

  public void setLinks(Links_ links) {
    this.links = links;
  }

  public String getAuthor() {
    return author;
  }

  public void setAuthor(String author) {
    this.author = author;
  }

  public Acl getAcl() {
    return acl;
  }

  public void setAcl(Acl acl) {
    this.acl = acl;
  }

  public Fields getFields() {
    return fields;
  }

  public void setFields(Fields fields) {
    this.fields = fields;
  }

  public Content getContent() {
    return content;
  }

  public void setContent(Content content) {
    this.content = content;
  }

}
