
package com.akamai.siem;

import java.util.List;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class InputStanza {

    @SerializedName("links")
    @Expose
    private Links links;
    @SerializedName("origin")
    @Expose
    private String origin;
    @SerializedName("updated")
    @Expose
    private String updated;
    @SerializedName("generator")
    @Expose
    private Generator generator;
    @SerializedName("entry")
    @Expose
    private List<Entry> entry = null;
    @SerializedName("paging")
    @Expose
    private Paging paging;
    @SerializedName("messages")
    @Expose
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
