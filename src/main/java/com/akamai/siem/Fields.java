
package com.akamai.siem;

import java.util.List;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class Fields {

    @SerializedName("required")
    @Expose
    private List<String> required = null;
    @SerializedName("optional")
    @Expose
    private List<String> optional = null;
    @SerializedName("wildcard")
    @Expose
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
