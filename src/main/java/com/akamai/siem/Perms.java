
package com.akamai.siem;

import java.util.List;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class Perms {

    @SerializedName("read")
    @Expose
    private List<String> read = null;
    @SerializedName("write")
    @Expose
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
