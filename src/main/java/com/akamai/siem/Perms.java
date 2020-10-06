
package com.akamai.siem;

import java.util.List;

public class Perms {

  private List<String> read = null;
  private List<String> write = null;

  public List<String> getRead() {
    return read;
  }

  public void setRead(List<String> read) {
    this.read = read;
  }

  public List<String> getWrite() {
    return write;
  }

  public void setWrite(List<String> write) {
    this.write = write;
  }

}
