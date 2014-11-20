package com.bcbs.sso.common.saml.model;

public class SamlProfileData {
	
	private String userId;
	private String secretKey;
	
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
	
	

}
