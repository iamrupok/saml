package com.bcbs.sso.common.saml.model;

public class BcbsSamlProfileData {
	
	private String userId;
	private String secretKey;
	private String destinationUrl;
	public String getUserId() {
		return userId;
	}
	public void setUserId(String userId) {
		this.userId = userId;
	}
	
	
	public String getSecretKey() {
		return secretKey;
	}
	public void setSecretKey(String secretKey) {
		this.secretKey = secretKey;
	}
	public String toString() {
        return "UserId: " + this.userId+ ",, "  + "SecretKey:" + this.secretKey;
    }
	public String getDestinationUrl() {
		return destinationUrl;
	}
	public void setDestinationUrl(String destinationUrl) {
		this.destinationUrl = destinationUrl;
	}
	
	

}
