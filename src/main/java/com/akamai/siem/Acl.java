
package com.akamai.siem;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class Acl {

    @SerializedName("app")
    @Expose
    private String app;
    @SerializedName("can_list")
    @Expose
    private Boolean canList;
    @SerializedName("can_write")
    @Expose
    private Boolean canWrite;
    @SerializedName("modifiable")
    @Expose
    private Boolean modifiable;
    @SerializedName("owner")
    @Expose
    private String owner;
    @SerializedName("perms")
    @Expose
    private Perms perms;
    @SerializedName("removable")
    @Expose
    private Boolean removable;
    @SerializedName("sharing")
    @Expose
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
