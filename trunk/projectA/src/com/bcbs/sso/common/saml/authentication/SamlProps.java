/*
 * @(#) UsmProps.java Aug 04, 2008
 * Copyright 2005 Frequency Marketing, Inc. All rights reserved.
 * Frequency Marketing, Inc. PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.bcbs.sso.common.saml.authentication;

import java.util.Map;

/**
 * All the properties are Configured in Spring.
 */
public class SamlProps
{
    private String m_keystore;
    private String m_issuer;
    private String m_audienceRestriction;
    private String m_samlPostURL;
    private String m_keystorePass;
    private String m_keystoreAlias;

    private String m_recipientURL;
  
    private Map <String,String > memberAttribute_BCBS;
   
      
    private boolean signatureRequired;
    private boolean encryptionRequired;
    
    
    private String partnerKeystore;
    private String partnerKeystorePass;
    private String partnerKeystoreAlias;  
    
    
	public boolean isSignatureRequired() {
		return signatureRequired;
	}

	public void setSignatureRequired(boolean signatureRequired) {
		this.signatureRequired = signatureRequired;
	}

	public boolean isEncryptionRequired() {
		return encryptionRequired; 
	}

	public void setEncryptionRequired(boolean encryptionRequired) {
		this.encryptionRequired = encryptionRequired;
	}

	public String getSamlPostURL()
    {
        return m_samlPostURL;
    }

    public void setSamlPostURL(String a_samlPostURL)
    {
        m_samlPostURL = a_samlPostURL;
    }

    public String getAudienceRestriction()
    {
        return m_audienceRestriction;
    }

    public void setAudienceRestriction(String a_audienceRestriction)
    {
        m_audienceRestriction = a_audienceRestriction;
    }

    public String getIssuer()
    {
        return m_issuer;
    }

    public void setIssuer(String a_issuer)
    {
        m_issuer = a_issuer;
    }

    public String getKeystore()
    {
        return m_keystore;
    }

    public void setKeystore(String a_keystore)
    {
        m_keystore = a_keystore;
    }

    /**
     * @return Returns the keystorePass.
     */
    public String getKeystorePass()
    {
        return m_keystorePass;
    }

    /**
     * @param a_keystorePass The keystorePass to set.
     */
    public void setKeystorePass(String a_keystorePass)
    {
        m_keystorePass = a_keystorePass;
    }

   

	public String getKeystoreAlias() 
	{
		return m_keystoreAlias;
	}

	public void setKeystoreAlias(String keystoreAlias) 
	{
		this.m_keystoreAlias = keystoreAlias;
	}

	

    public String getRecipientURL() {
		return m_recipientURL;
	}

	public void setRecipientURL(String recipientURL) {
		this.m_recipientURL = recipientURL;
	}

	public Map<String, String> getMemberAttribute_BCBS() {
		return memberAttribute_BCBS;
	}

	public void setMemberAttribute_BCBS(Map<String, String> memberAttribute_BCBS) {
		this.memberAttribute_BCBS = memberAttribute_BCBS;
	}

	public String getPartnerKeystore() {
		return partnerKeystore;
	}

	public void setPartnerKeystore(String partnerKeystore) {
		this.partnerKeystore = partnerKeystore;
	}

	public String getPartnerKeystorePass() {
		return partnerKeystorePass;
	}

	public void setPartnerKeystorePass(String partnerKeystorePass) {
		this.partnerKeystorePass = partnerKeystorePass;
	}

	public String getPartnerKeystoreAlias() {
		return partnerKeystoreAlias;
	}

	public void setPartnerKeystoreAlias(String partnerKeystoreAlias) {
		this.partnerKeystoreAlias = partnerKeystoreAlias;
	}

	
	
		
	
}
