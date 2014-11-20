package com.bcbs.sso.saml.grcode;

import java.security.KeyStore;
import java.util.Map;

import com.bcbs.sso.saml.StringUtils;

public class SAMLData {
	
	private String inReponseTo; /* saml in response to */
	private String destination;
	private String nameValue;
	private String nameIdFormat; /* default to unspecified */
	private String subjectConfirmationMethod; /* defaults to bearer */ 
	private String issuerUrl;
	private String issuerFormat; /* defaults to entity */
	private String restrictedAudience;
	private int sessionTimeout;
	private String sessionId;
	private String audienceRestrictionUrl;
	private String authClassReference;/* default to unspecified */
	private KeyStore.PrivateKeyEntry privateKeyEntry;
	private String samlPostURL;
	private Map<String,String> customAttributes;
	private String receipientUrl;
	
	public String getReceipientUrl() {
		return receipientUrl;
	}
	public void setReceipientUrl(String receipientUrl) {
		this.receipientUrl = receipientUrl;
	}
	public String getInReponseTo() {
		return inReponseTo;
	}
	public void setInReponseTo(String inReponseTo) {
		this.inReponseTo = inReponseTo;
	}
	public String getNameValue() {
		return nameValue;
	}
	public void setNameValue(String nameValue) {
		this.nameValue = nameValue;
	}

	public String getNameIdFormat() {
		return nameIdFormat;
	}
	public void setNameIdFormat(String nameIdFormat) {
		this.nameIdFormat = nameIdFormat;
	}
	
	public String getSubjectConfirmationMethod() {
		return subjectConfirmationMethod;
	}
	public void setSubjectConfirmationMethod(String subjectConfirmationMethod) {
		this.subjectConfirmationMethod = subjectConfirmationMethod;
	}
	public String getIssuerUrl() {
		return issuerUrl;
	}
	public void setIssuerUrl(String issuerUrl) {
		this.issuerUrl = issuerUrl;
	}
	public String getRestrictedAudience() {
		return restrictedAudience;
	}
	public void setRestrictedAudience(String restrictedAudience) {
		this.restrictedAudience = restrictedAudience;
	}
	
	
	
	public int getSessionTimeout() {
		return sessionTimeout;
	}
	public void setSessionTimeout(int sessionTimeout) {
		this.sessionTimeout = sessionTimeout;
	}
	
	
	
	
	public String getSessionId() {
		return sessionId;
	}
	public void setSessionId(String sessionId) {
		this.sessionId = sessionId;
	}
	
	
	
	public Map<String, String> getCustomAttributes() {
		return customAttributes;
	}
	public void setCustomAttributes(Map<String, String> customAttributes) {
		this.customAttributes = customAttributes;
	}
	/*@Override
	public String toString()
	{
		return StringUtils.toStringObject(this);
	}*/
	public KeyStore.PrivateKeyEntry getPrivateKeyEntry() {
		return privateKeyEntry;
	}
	public void setPrivateKeyEntry(KeyStore.PrivateKeyEntry privateKeyEntry) {
		this.privateKeyEntry = privateKeyEntry;
	}
	public String getIssuerFormat() {
		return issuerFormat;
	}
	public void setIssuerFormat(String issuerFormat) {
		this.issuerFormat = issuerFormat;
	}
	public String getAudienceRestrictionUrl() {
		return audienceRestrictionUrl;
	}
	public void setAudienceRestrictionUrl(String audienceRestrictionUrl) {
		this.audienceRestrictionUrl = audienceRestrictionUrl;
	}
	public String getAuthClassReference() {
		return authClassReference;
	}
	public void setAuthClassReference(String authClassReference) {
		this.authClassReference = authClassReference;
	}
	public String getSamlPostURL() {
		return samlPostURL;
	}
	public void setSamlPostURL(String samlPostURL) {
		this.samlPostURL = samlPostURL;
	}
	public String getDestination() {
		return destination;
	}
	public void setDestination(String destination) {
		this.destination = destination;
	}
	
	
	
}
