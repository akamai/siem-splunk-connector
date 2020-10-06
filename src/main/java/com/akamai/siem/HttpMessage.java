package com.akamai.siem;

public class HttpMessage {

  private String requestId;
  private String start;
  private String protocol;
  private String method;
  private String host;
  private String port;
  private String path;
  private String query;
  private String requestHeaders;
  private String status;
  private String bytes;
  private String responseHeaders;
  private String tls;

  public void processRaw() {
    this.requestHeaders = decode(this.requestHeaders);
    this.responseHeaders = decode(this.responseHeaders);
    this.query = decode(this.query);
  }

  /*
   * URL decode
   */
  private String decode(String s) {
    String urlDecodeValue = s;
    try {
      if (urlDecodeValue != null) {
        urlDecodeValue = java.net.URLDecoder.decode(s, "UTF-8");
      }
    } catch (Exception ex) {
    }
    return (urlDecodeValue);
  }

  public String getRequestId() {
    return requestId;
  }

  public void setRequestId(String requestId) {
    this.requestId = requestId;
  }

  public String getStart() {
    return start;
  }

  public void setStart(String start) {
    this.start = start;
  }

  public String getProtocol() {
    return protocol;
  }

  public void setProtocol(String protocol) {
    this.protocol = protocol;
  }

  public String getMethod() {
    return method;
  }

  public void setMethod(String method) {
    this.method = method;
  }

  public String getHost() {
    return host;
  }

  public void setHost(String host) {
    this.host = host;
  }

  public String getPort() {
    return port;
  }

  public void setPort(String port) {
    this.port = port;
  }

  public String getPath() {
    return path;
  }

  public void setPath(String path) {
    this.path = path;
  }

  public String getQuery() {
    return query;
  }

  public void setQuery(String query) {
    this.query = query;
  }

  public String getRequestHeaders() {
    return requestHeaders;
  }

  public void setRequestHeaders(String requestHeaders) {
    this.requestHeaders = requestHeaders;
  }

  public String getStatus() {
    return status;
  }

  public void setStatus(String status) {
    this.status = status;
  }

  public String getBytes() {
    return bytes;
  }

  public void setBytes(String bytes) {
    this.bytes = bytes;
  }

  public String getResponseHeaders() {
    return responseHeaders;
  }

  public void setResponseHeaders(String responseHeaders) {
    this.responseHeaders = responseHeaders;
  }

  public String getTls() {
    return tls;
  }

  public void setTls(String tls) {
    this.tls = tls;
  }
}
