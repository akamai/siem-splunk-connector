
package com.akamai.siem;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class Paging {

    @SerializedName("total")
    @Expose
    private Integer total;
    @SerializedName("perPage")
    @Expose
    private Integer perPage;
    @SerializedName("offset")
    @Expose
    private Integer offset;

    public Integer getTotal() {
        return total;
    }

    public void setTotal(Integer total) {
        this.total = total;
    }

    public Integer getPerPage() {
        return perPage;
    }

    public void setPerPage(Integer perPage) {
        this.perPage = perPage;
    }

    public Integer getOffset() {
        return offset;
    }

    public void setOffset(Integer offset) {
        this.offset = offset;
    }

}
