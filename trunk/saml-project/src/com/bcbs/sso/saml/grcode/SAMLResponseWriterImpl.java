package com.bcbs.sso.saml.grcode;

import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

/**
 * @author sshaik
 *
 * Class to generate SAML Response including Signing, encoding and encryption.
 */
public class SAMLResponseWriterImpl extends SAML implements SAMLResponseWriter 
{
	private static Log logger = LogFactory.getLog(SAMLResponseWriterImpl.class);

	
	
	public String getSAMLResponse(SAMLData samlData) 
	{
		DateTime timeAtWritignThisSamlResponse = new DateTime(DateTimeZone.UTC);
		String samlReponse = null;
		Response response = null;
		
		// Step 1 create Issuer
		
		Issuer issuer = create (Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue (samlData.getIssuerUrl());
        issuer.setFormat(ISSUER_FORMAT_PREFIX  + (null != samlData.getIssuerFormat() ? samlData.getIssuerFormat() : "entity")); 
		
		// Step 2 Create Subject.
		//logger.debug("Base Data Vaues ----> "+ samlData.toString());
		Subject subject = createSubject(samlData);
		
		NameID nameID = create(NameID.class, NameID.DEFAULT_ELEMENT_NAME);
		nameID.setValue(samlData.getNameValue());
		if (samlData.getNameIdFormat() != null){
			//nameID.setFormat(NAMEID_FORMAT_PREFIX+samlData.getNameIdFormat());
			nameID.setFormat(NameID.UNSPECIFIED);
		}
		else{
			
			nameID.setFormat(NAMEID_FORMAT_PREFIX);
		}
		
		subject.setNameID(nameID);
		
		
		// Step 3 Create Authentication Statement.
		 AuthnStatement authnStatement  = 
				 create(AuthnStatement.class,AuthnStatement.DEFAULT_ELEMENT_NAME);
		 
		 
		 authnStatement.setAuthnInstant(timeAtWritignThisSamlResponse);
		 authnStatement.setSessionIndex(samlData.getSessionId());
		 authnStatement.setSessionNotOnOrAfter(
				 timeAtWritignThisSamlResponse.plusMinutes(samlData.getSessionTimeout()));
		 
		
		  AuthnContextClassRef authnContextClassRef  = 
				  create(AuthnContextClassRef.class,AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		  authnContextClassRef.setAuthnContextClassRef(AUTH_CLASS_REF_PREFIX +
				  null != samlData.getAuthClassReference() ?
				  samlData.getAuthClassReference() :  "unspecified");
				  
		  
		   AuthnContext authnContext = create(AuthnContext.class,AuthnContext.DEFAULT_ELEMENT_NAME);
		   authnContext.setAuthnContextClassRef(authnContextClassRef);
		   authnStatement.setAuthnContext(authnContext);
		   
		   // Step 4 Create Conditions.
		   Conditions conditions = create 
		            (Conditions.class, Conditions.DEFAULT_ELEMENT_NAME);
		       /* conditions.setNotBefore (timeAtWritignThisSamlResponse.minusSeconds (15));
		        conditions.setNotOnOrAfter (timeAtWritignThisSamlResponse.plusMinutes(2));*/
		   conditions.setNotBefore (timeAtWritignThisSamlResponse);
	        conditions.setNotOnOrAfter (timeAtWritignThisSamlResponse.plusMinutes(15));
		        
		        
		        if(null != samlData.getAudienceRestrictionUrl())
		        {
			        AudienceRestriction audidenceRestriction = create(AudienceRestriction.class,AudienceRestriction.DEFAULT_ELEMENT_NAME);
			        Audience audience = create(Audience.class, Audience.DEFAULT_ELEMENT_NAME);
			        audience.setAudienceURI(samlData.getAudienceRestrictionUrl());
			        audidenceRestriction.getAudiences().add(audience);
			        conditions.getAudienceRestrictions().add(audidenceRestriction);
		        
		        }
		        
		        
		        
		        
		  // Step 5 Create custom Attributes.
		        AttributeStatement attribute = addAttributes(samlData.getCustomAttributes());
		        
		  //  Step 6 Create Assertion and set all the above objects to the assertion object.
		        
		     Assertion assertion = 
		                create (Assertion.class, Assertion.DEFAULT_ELEMENT_NAME);
		     
		     //   Assertion assertion = createAssertion(subject, 1, 2);
		     
		     assertion.setIssueInstant(timeAtWritignThisSamlResponse);
		     assertion.setIssuer(issuer);
		     assertion.setSubject(subject);
		     assertion.getAuthnStatements().add(authnStatement);
		     assertion.setConditions(conditions);
		     assertion.getAttributeStatements().add(attribute);
		     assertion.setID(getGUID());
		     //Signed key
		     assertion= signAssertionNew(assertion,samlData.getPrivateKeyEntry());
		     if(logger.isDebugEnabled())
		     {
		     try{
		    	 	printToFile(assertion, null);
		     }catch(Exception e)
		     {
		    	 logger.error("Error while printing SAML");
		    	 e.printStackTrace();
		     }
		     		    
		     }
		    
		     try{
		    	 //response = createResponse(assertion,samlData.getInReponseTo());		    	 	
		    	 response = createResponse(assertion,samlData.getInReponseTo(), samlData.getDestination());
		     }catch(Exception e)
		     {
		    	 logger.error("Error while creating  response  " + e.getMessage());
		    	 e.printStackTrace();
		     }
		     
		  // Step 7 Sign the response;
		    /* 
		     if(null != samlData.getPrivateKeyEntry())
		     {
		    	 signResponse(response,samlData.getPrivateKeyEntry());
		     }*/
		     
		    try {
			 	ResponseMarshaller marshaller = new ResponseMarshaller();
				Element plain = marshaller.marshall(response);
				if(null == plain){
					logger.error("Element is plain " );
				}
				samlReponse = XMLHelper.nodeToString(plain);
			} catch (MarshallingException e) {
				samlReponse="";
				logger.error("Errorr while marshalling ",e);
				e.printStackTrace();
			}
			return samlReponse;
	}
	
	
	public String getSAMLAssertion(SAMLData samlData) 
	{
		DateTime timeAtWritignThisSamlResponse = new DateTime();
		String samlAssertion = null;
		
		Response response = null;
		
		// Step 1 create Issuer
		
		Issuer issuer = create (Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue (samlData.getIssuerUrl());
        issuer.setFormat(ISSUER_FORMAT_PREFIX  + (null != samlData.getIssuerFormat() ? samlData.getIssuerFormat() : "entity")); 
		
		// Step 2 Create Subject.
		logger.debug("Base Data Vaues ----> "+ samlData.toString());
		Subject subject = createSubject(samlData);
		
		
		// Step 3 Create Authentication Statement.
		 AuthnStatement authnStatement  = 
				 create(AuthnStatement.class,AuthnStatement.DEFAULT_ELEMENT_NAME);
		 
		 
		 authnStatement.setAuthnInstant(timeAtWritignThisSamlResponse);
		 authnStatement.setSessionIndex(samlData.getSessionId());
		 authnStatement.setSessionNotOnOrAfter(
				 timeAtWritignThisSamlResponse.plusMinutes(samlData.getSessionTimeout()));
		 
		
		  AuthnContextClassRef authnContextClassRef  = 
				  create(AuthnContextClassRef.class,AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		  authnContextClassRef.setAuthnContextClassRef(AUTH_CLASS_REF_PREFIX +
				  null != samlData.getAuthClassReference() ?
				  samlData.getAuthClassReference() :  "unspecified");
				  
		  
		   AuthnContext authnContext = create(AuthnContext.class,AuthnContext.DEFAULT_ELEMENT_NAME);
		   authnContext.setAuthnContextClassRef(authnContextClassRef);
		   authnStatement.setAuthnContext(authnContext);
		   
		   // Step 4 Create Conditions.
		   Conditions conditions = create 
		            (Conditions.class, Conditions.DEFAULT_ELEMENT_NAME);
		        conditions.setNotBefore (timeAtWritignThisSamlResponse.minusSeconds (15));
		        conditions.setNotOnOrAfter (timeAtWritignThisSamlResponse.plusMinutes(2));
		        
		        
		        if(null != samlData.getAudienceRestrictionUrl())
		        {
			        AudienceRestriction audidenceRestriction = create(AudienceRestriction.class,AudienceRestriction.DEFAULT_ELEMENT_NAME);
			        Audience audience = create(Audience.class, Audience.DEFAULT_ELEMENT_NAME);
			        audience.setAudienceURI(samlData.getAudienceRestrictionUrl());
			        audidenceRestriction.getAudiences().add(audience);
			        conditions.getAudienceRestrictions().add(audidenceRestriction);
		        
		        }
		        
		        
		        
		        
		  // Step 5 Create custom Attributes.
		        AttributeStatement attribute = addAttributes(samlData.getCustomAttributes());
		        
		  //  Step 6 Create Assertion and set all the above objects to the assertion object.
		        
		     Assertion assertion = 
		                create (Assertion.class, Assertion.DEFAULT_ELEMENT_NAME);
		     
		     
		     assertion.setIssueInstant(timeAtWritignThisSamlResponse);
		     assertion.setIssuer(issuer);
		     assertion.setSubject(subject);
		     assertion.getAuthnStatements().add(authnStatement);
		     assertion.setConditions(conditions);
		     assertion.getAttributeStatements().add(attribute);
		     
		     if(logger.isDebugEnabled())
		     {
		     try{
		    	 	printToFile(assertion, null);
		     }catch(Exception e)
		     {
		    	 logger.error("Error while printing SAML");
		    	 e.printStackTrace();
		     }
		     		    
		     }
		    
		    /* try{
		    	 response = createResponse(assertion,samlData.getInReponseTo());		    	 	
		     }catch(Exception e)
		     {
		    	 logger.error("Error while creating  response  " + e.getMessage());
		    	 e.printStackTrace();
		     }*/
		     
		  // Step 7 Sign the response;
		     
		     if(null != samlData.getPrivateKeyEntry())
		     {
		    	 samlAssertion =  signAssertion(assertion,samlData.getPrivateKeyEntry());
		     }
		     
		   /* try {
			 	ResponseMarshaller marshaller = new ResponseMarshaller();
				Element plain = marshaller.marshall(response);
				if(null == plain){
					logger.error("Element is plain " );
				}
				samlReponse = XMLHelper.nodeToString(plain);
			} catch (MarshallingException e) {
				samlReponse="";
				logger.error("Errorr while marshalling ",e);
				e.printStackTrace();
			}*/
			return samlAssertion;
	}
	
	private String getGUID()
	{
		UUID uuid = UUID.randomUUID();
		return uuid.toString();
	}
	
}
