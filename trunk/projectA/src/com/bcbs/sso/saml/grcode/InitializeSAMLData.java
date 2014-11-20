package com.bcbs.sso.saml.grcode;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.log4j.Logger;

import sun.misc.BASE64Encoder;

import com.bcbs.sso.common.saml.authentication.SamlProps;
import com.bcbs.sso.common.saml.model.SamlProfileData;
import com.bcbs.sso.saml.CryptoXml;
import com.bcbs.sso.saml.StringUtils;

public class InitializeSAMLData {
	
	public static final String BCBS_PARTNER_ID = "BCBS";
	
	
	//private static Log s_logger = LogFactory.getLog(InitializeSAMLData.class);
	
	 static Logger s_logger = Logger.getLogger(InitializeSAMLData.class);
	
	
	/*
	 * Gets MemberProfileAttributes profile map
	 * @Params Object memberProfile,Map propertiesMap,sessionId
	 * @return Map
	 */
	public Map createSAMLCustomAttributes(Object memberProfile, Map propertiesMap,String sessionId) throws Exception
	{
		Map attributeMap=(HashMap<String, Object>) BeanUtils.describe(memberProfile);
		Map memberAttributes = new HashMap();
		memberAttributes=populateMemberProfileAttributes(attributeMap,propertiesMap, sessionId);
	    return memberAttributes;
	}
	/*
	 * Populate the memberAttributes Map with Member data
	 * @Params  Map attributeMap,propertiesMap, sessionId
	 * @return  Map
	 */
	public Map populateMemberProfileAttributes(Map attributeMap,Map propertiesMap, String sessionId) throws Exception{
		Map memberAttributes = new HashMap();
		Iterator propertiesMapIterator=propertiesMap.entrySet().iterator();
		while(propertiesMapIterator.hasNext()){
			Map.Entry pairs=(Map.Entry)propertiesMapIterator.next();
			if(pairs.getValue().equals("sessionId"))
			{
				memberAttributes.put(pairs.getValue(), sessionId);
			}
			else{
				memberAttributes.put(pairs.getValue(), attributeMap.get(pairs.getKey()));
			}
		}
		
		
		 return memberAttributes;
		 
	}
	
	

	public void initializeSAMLData(String partnerId, SamlProps props,SamlProfileData memberData,HttpServletRequest request  ) throws Exception
	{	
		
		Map memberAttributesMap = new HashMap();
		SAMLData samlData = new SAMLData();
		
        if(!StringUtils.isEmpty(partnerId) && partnerId.equals(BCBS_PARTNER_ID) || partnerId.equals(BCBS_PARTNER_ID))
        {
        	
        	memberAttributesMap=props.getMemberAttribute_BCBS();
        	
            samlData.setCustomAttributes(createSAMLCustomAttributes(memberData, memberAttributesMap, request.getSession().getId()));
           
        }  
        
		
		samlData.setIssuerUrl(props.getIssuer());
		samlData.setNameValue(memberData.getUserId());
		samlData.setAudienceRestrictionUrl(props.getAudienceRestriction());
		samlData.setReceipientUrl(props.getRecipientURL());
		samlData.setSessionId(request.getSession().getId());
		samlData.setDestination("http://dmawbicobo01.bico.edm:8080/BOE/BI/custom.jsp");
		samlData.setSessionTimeout(6); //TODO
		samlData.setSamlPostURL(props.getSamlPostURL());

		if(props.isSignatureRequired()){
   			KeyStore keystore = KeystoreUtil.getKeyStore(props.getKeystore(), props.getKeystorePass().toCharArray());
   	   		KeyStore.PrivateKeyEntry privateKeyEntry = KeystoreUtil.getPrivateKeyEntry(keystore, props.getKeystoreAlias(), props.getKeystorePass());
   	   		samlData.setPrivateKeyEntry(privateKeyEntry);
   		}
   	
   		SAMLResponseWriter writer  = new SAMLResponseWriterImpl();						
		String samlResponse = writer.getSAMLResponse(samlData);
		s_logger.debug("\n\n\n saml response to BO:--> " + samlResponse);	
		System.out.println("Generated Response: "+samlResponse);
		
		
		if(props.isEncryptionRequired()){
			String encryptedSamlResponse = CryptoXml.encryptPartner(samlResponse, props);		
					
			s_logger.debug("\n\n\n Encrypted saml response to partner:--> " + encryptedSamlResponse);
			request.getSession().setAttribute("SAMLURL", samlData.getSamlPostURL());			
			request.getSession().setAttribute("SAMLResponse", encryptedSamlResponse ); 
			
		}
		else
		{			
			request.getSession().setAttribute("SAMLURL", samlData.getSamlPostURL());
			BASE64Encoder encoder = new BASE64Encoder();		
			request.getSession().setAttribute("SAMLResponse", encoder.encodeBuffer(samlResponse.toString().getBytes()) );
		}
		
	}
	
 }
