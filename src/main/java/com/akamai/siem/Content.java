
package com.akamai.siem;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class Content {

	@SerializedName("access_token")
	@Expose
	private String accessToken;
	@SerializedName("client_secret")
	@Expose
	private String clientSecret;
	@SerializedName("client_token")
	@Expose
	private String clientToken;
	@SerializedName("disabled")
	@Expose
	private Boolean disabled;
	@SerializedName("eai:acl")
	@Expose
	private Object eaiAcl;
	@SerializedName("final_epoch_time")
	@Expose
	private Integer finalEpochTime;
	@SerializedName("host")
	@Expose
	private String host;
	@SerializedName("host_resolved")
	@Expose
	private String hostResolved;
	@SerializedName("hostname")
	@Expose
	private String hostname;
	@SerializedName("index")
	@Expose
	private String index;
	@SerializedName("initial_epoch_time")
	@Expose
	private Integer initialEpochTime;
	@SerializedName("interval")
	@Expose
	private String interval;
	@SerializedName("limit")
	@Expose
	private Integer limit;
	@SerializedName("log_level")
	@Expose
	private String logLevel;
	@SerializedName("security_configuration_id_s_")
	@Expose
	private String securityConfigurationIdS;
	@SerializedName("sourcetype")
	@Expose
	private String sourcetype;
	@SerializedName("start_by_shell")
	@Expose
	private String startByShell;

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public String getClientToken() {
		return clientToken;
	}

	public void setClientToken(String clientToken) {
		this.clientToken = clientToken;
	}

	public Boolean getDisabled() {
		return disabled;
	}

	public void setDisabled(Boolean disabled) {
		this.disabled = disabled;
	}

	public Object getEaiAcl() {
		return eaiAcl;
	}

	public void setEaiAcl(Object eaiAcl) {
		this.eaiAcl = eaiAcl;
	}

	public Integer getFinalEpochTime() {
		return finalEpochTime;
	}

	public void setFinalEpochTime(Integer finalEpochTime) {
		this.finalEpochTime = finalEpochTime;
	}

	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public String getHostResolved() {
		return hostResolved;
	}

	public void setHostResolved(String hostResolved) {
		this.hostResolved = hostResolved;
	}

	public String getHostname() {
		return hostname;
	}

	public void setHostname(String hostname) {
		this.hostname = hostname;
	}

	public String getIndex() {
		return index;
	}

	public void setIndex(String index) {
		this.index = index;
	}

	public Integer getInitialEpochTime() {
		return initialEpochTime;
	}

	public void setInitialEpochTime(Integer initialEpochTime) {
		this.initialEpochTime = initialEpochTime;
	}

	public String getInterval() {
		return interval;
	}

	public void setInterval(String interval) {
		this.interval = interval;
	}

	public Integer getLimit() {
		return limit;
	}

	public void setLimit(Integer limit) {
		this.limit = limit;
	}

	public String getLogLevel() {
		return logLevel;
	}

	public void setLogLevel(String logLevel) {
		this.logLevel = logLevel;
	}

	public String getSecurityConfigurationIdS() {
		return securityConfigurationIdS;
	}

	public void setSecurityConfigurationIdS(String securityConfigurationIdS) {
		this.securityConfigurationIdS = securityConfigurationIdS;
	}

	public String getSourcetype() {
		return sourcetype;
	}

	public void setSourcetype(String sourcetype) {
		this.sourcetype = sourcetype;
	}

	public String getStartByShell() {
		return startByShell;
	}

	public void setStartByShell(String startByShell) {
		this.startByShell = startByShell;
	}

}
