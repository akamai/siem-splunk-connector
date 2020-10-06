package com.akamai.siem;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

import com.fasterxml.jackson.annotation.JsonRawValue;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;

public class Raw {

  private String type;
  private String format;
  private String version;
  @JsonRawValue
  private Object custom;
  private AttackData attackData;
  private HttpMessage httpMessage;
  private Geo geo;

  // last line only
  private Integer total;
  private String offset;
  private Integer limit;

  public void processRaw() throws UnsupportedEncodingException {
    if (attackData != null) {
      attackData.processRaw();
    }
    if (httpMessage != null) {
      httpMessage.processRaw();
    }
    if (custom != null) {
      custom = decodeCustom(custom);
    }
  }

  private String decodeCustom(Object rawCustom) throws UnsupportedEncodingException {

    try {
      Custom custom = Main.mapper.readValue(rawCustom.toString(), Custom.class);

      String urlDecodeValue = custom.getCustomValue();
      try {
        urlDecodeValue = java.net.URLDecoder.decode(urlDecodeValue, "UTF-8");
      } catch (Exception ex) {
      }

      String[] tokenizedResult = {urlDecodeValue};
      tokenizedResult = urlDecodeValue.split(";");


      if (tokenizedResult.length > 1) {
        ArrayList<String> decodedValues = new ArrayList<String>();
        for (String s : tokenizedResult) {
          String[] detectSpaces = s.split(" ");
          StringBuilder sb2 = new StringBuilder();
          for (String ss : detectSpaces) {
            if (sb2.length() > 0) {
              sb2.append(" ");
            }
            sb2.append(new String(org.apache.commons.codec.binary.Base64.decodeBase64(ss), StandardCharsets.UTF_8));
          }
          decodedValues.add(sb2.toString());
        }

        CustomArray ca = new CustomArray();
        ca.setCustomKey(custom.getCustomKey());
        ca.setCustomValue(decodedValues);
        return (Main.mapper.writeValueAsString(ca));

      } else if (tokenizedResult.length > 0) {
        String[] detectSpaces = tokenizedResult[0].split(" ");
        StringBuilder sb2 = new StringBuilder();
        for (String ss : detectSpaces) {
          if (sb2.length() > 0) {
            sb2.append(" ");
          }
          sb2.append(new String(org.apache.commons.codec.binary.Base64.decodeBase64(ss), StandardCharsets.UTF_8));
        }
        custom.setCustomValue(sb2.toString());
        return (Main.mapper.writeValueAsString(custom));
      } else {

      }

    } catch (JsonProcessingException e) {
      e.printStackTrace();
    }

    return (rawCustom.toString());
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public String getFormat() {
    return format;
  }

  public void setFormat(String format) {
    this.format = format;
  }

  public String getVersion() {
    return version;
  }

  public void setVersion(String version) {
    this.version = version;
  }

  @JsonRawValue
  public String getCustom() {
    return custom == null ? null : custom.toString();
  }

  public void setCustom(JsonNode custom) {
    this.custom = custom;
  }

  public AttackData getAttackData() {
    return attackData;
  }

  public void setAttackData(AttackData attackData) {
    this.attackData = attackData;
  }

  public HttpMessage getHttpMessage() {
    return httpMessage;
  }

  public void setHttpMessage(HttpMessage httpMessage) {
    this.httpMessage = httpMessage;
  }

  public Geo getGeo() {
    return geo;
  }

  public void setGeo(Geo geo) {
    this.geo = geo;
  }

  public Integer getTotal() {
    return total;
  }

  public void setTotal(Integer total) {
    this.total = total;
  }

  public String getOffset() {
    return offset;
  }

  public void setOffset(String offset) {
    this.offset = offset;
  }

  public Integer getLimit() {
    return limit;
  }

  public void setLimit(Integer limit) {
    this.limit = limit;
  }
}
