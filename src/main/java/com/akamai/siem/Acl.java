
package com.akamai.siem;

public class Acl {

  private String app;
  private Boolean canList;
  private Boolean canWrite;
  private Boolean modifiable;
  private String owner;
  private Perms perms;
  private Boolean removable;
  private String sharing;

  public String getApp() {
    return app;
  }

  public void setApp(String app) {
    this.app = app;
  }

  public Boolean getCanList() {
    return canList;
  }

  public void setCanList(Boolean canList) {
    this.canList = canList;
  }

  public Boolean getCanWrite() {
    return canWrite;
  }

  public void setCanWrite(Boolean canWrite) {
    this.canWrite = canWrite;
  }

  public Boolean getModifiable() {
    return modifiable;
  }

  public void setModifiable(Boolean modifiable) {
    this.modifiable = modifiable;
  }

  public String getOwner() {
    return owner;
  }

  public void setOwner(String owner) {
    this.owner = owner;
  }

  public Perms getPerms() {
    return perms;
  }

  public void setPerms(Perms perms) {
    this.perms = perms;
  }

  public Boolean getRemovable() {
    return removable;
  }

  public void setRemovable(Boolean removable) {
    this.removable = removable;
  }

  public String getSharing() {
    return sharing;
  }

  public void setSharing(String sharing) {
    this.sharing = sharing;
  }

}
