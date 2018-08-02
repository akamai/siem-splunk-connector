
package com.akamai.siem;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class Links_ {

    @SerializedName("alternate")
    @Expose
    private String alternate;
    @SerializedName("list")
    @Expose
    private String list;
    @SerializedName("_reload")
    @Expose
    private String reload;
    @SerializedName("edit")
    @Expose
    private String edit;
    @SerializedName("remove")
    @Expose
    private String remove;
    @SerializedName("disable")
    @Expose
    private String disable;

    public String getAlternate() {
        return alternate;
    }

    public void setAlternate(String alternate) {
        this.alternate = alternate;
    }

    public String getList() {
        return list;
    }

    public void setList(String list) {
        this.list = list;
    }

    public String getReload() {
        return reload;
    }

    public void setReload(String reload) {
        this.reload = reload;
    }

    public String getEdit() {
        return edit;
    }

    public void setEdit(String edit) {
        this.edit = edit;
    }

    public String getRemove() {
        return remove;
    }

    public void setRemove(String remove) {
        this.remove = remove;
    }

    public String getDisable() {
        return disable;
    }

    public void setDisable(String disable) {
        this.disable = disable;
    }

}
