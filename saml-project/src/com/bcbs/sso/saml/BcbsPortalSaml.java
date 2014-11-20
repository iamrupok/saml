package com.bcbs.sso.saml;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.log4j.Logger;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.bcbs.sso.common.saml.authentication.SamlProps;
import com.bcbs.sso.common.saml.model.BcbsSamlProfileData;
import com.bcbs.sso.saml.grcode.CustomSAMLException;
import com.bcbs.sso.saml.grcode.KeystoreUtil;


public class BcbsPortalSaml {

	static Logger s_logger = Logger.getLogger(BcbsPortalSaml.class);
	
    public SamlProps samlProps;
    public CryptoXml cryptoXml;

    public static final String DEFAULT_ORIGINATOR = "BCBSLOGIN";


	public BcbsSamlProfileData processLoginResponseSAML2(String  loginSAMLResponse) throws Exception 
	{ 
	  org.opensaml.DefaultBootstrap.bootstrap();
	  String strSamlResponse = loginSAMLResponse;
		
	  if(getSamlProps().isEncryptionRequired())
	  {
	    strSamlResponse = cryptoXml.decrypt(loginSAMLResponse);
	    // System.out.println(strSamlResponse);
		s_logger.debug("Decrypted Login SAML Response: " + strSamlResponse);
	  }
	 
	  
	  BcbsSamlProfileData  bcbsSamlProfileData  = new BcbsSamlProfileData();
	  
	  ByteArrayInputStream is =  new ByteArrayInputStream(strSamlResponse.getBytes());
	  
	 /* SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
	  Schema schema = schemaFactory.newSchema(new URL("http://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd"));
	  */
	  DocumentBuilderFactory documentBuilderFactory =   DocumentBuilderFactory.newInstance();
	  documentBuilderFactory.setNamespaceAware(true); 
	  //documentBuilderFactory.setSchema(schema);
	  DocumentBuilder  docBuilder = documentBuilderFactory.newDocumentBuilder();
	  
	  Document document = docBuilder.parse(is); 
	  Element element =  document.getDocumentElement();
	  
	  
	  UnmarshallerFactory unmarshallerFactory =  org.opensaml.Configuration.getUnmarshallerFactory();
	  org.opensaml.xml.io.Unmarshaller unmarshaller =   unmarshallerFactory.getUnmarshaller(element); 
	  XMLObject responseXmlObj =  (XMLObject)unmarshaller.unmarshall(element);
	  
	  
	  Response samlResponse = (Response) responseXmlObj;
	  /*
	  Signature sig = samlResponse.getSignature(); 
	  // Validating the signature 
	  SignatureValidator validator = new SignatureValidator(credential); 
	  validator.validate(sig);
	  */
	  /************************** Print the Response as XML String *****************************************/

		ResponseMarshaller marshaller = new ResponseMarshaller();
		Element plain;
		String response = null;
		try {
			plain = marshaller.marshall(samlResponse);
			response = XMLHelper.nodeToString(plain);
			s_logger.info("Received Response: "+response);
			//System.out.println("Received Response: "+response);
		} catch (MarshallingException e) {
			e.printStackTrace();
		}
	  
	  if (samlResponse != null) 
	  { //response.verify(certificate);
		  
		  Iterator<Assertion> iterator  = samlResponse.getAssertions().iterator();
		  
		  while (iterator.hasNext()) 
		  {
				  
			  
			  Assertion assertion = (Assertion)iterator.next();
			  //assertion.checkValidity();
			  if(isValidSamlAssertionSignature(assertion, getSamlProps())){
				  
				  org.joda.time.DateTime notB = assertion.getConditions().getNotBefore();
				  org.joda.time.DateTime notOnOrA =  assertion.getConditions().getNotOnOrAfter();
				  
				  Date notBefore = notB.toDate(); 
				  Date notOnOrAfter = notOnOrA.toDate();
				  
				  if(isDateValid(notBefore, notOnOrAfter)) 
				  {
				  
					  Iterator aserItr = assertion.getStatements().iterator();
					  if (aserItr.hasNext()) 
					  { 
						  AuthnStatement statement = (AuthnStatement)	  aserItr.next();
					  } 
					  if(aserItr.hasNext()) 
					  { 
						  AttributeStatement attribStmt =  (AttributeStatement) aserItr.next();
					  
						  Iterator attribItr = attribStmt.getAttributes().iterator();
					  
						  while(attribItr.hasNext()) 
						  { 
							  Attribute samlAttr =  (Attribute)attribItr.next(); 
							  if(samlAttr.getName() != null &&  samlAttr.getName().equals("userId")) 
							  { 
								  XMLObject obj =   samlAttr.getAttributeValues().get(0); 
								  if(obj != null) 
								  { 
									  bcbsSamlProfileData.setUserId(obj.getDOM().getTextContent()); 
									  //bcbsSamlProfileData.setUserId(new String(Base64.decodeBase64(obj.getDOM().getTextContent())));
								  } 
							  } 
							  if(samlAttr.getName() != null &&  samlAttr.getName().equals("secretKey")) 
							  { 
								  XMLObject obj =   samlAttr.getAttributeValues().get(0); 
								  if(obj != null) 
								  { 
									  bcbsSamlProfileData.setSecretKey(obj.getDOM().getTextContent()); 
									 
								  } 
							  } 
						  } 
					  }
				  
				  } 
				  else 
				  { 
					  s_logger.error("SAML Response expired. notBefore: " + notBefore  + "   notOnOrAfter: " + notOnOrAfter + "     current time: " +
					  Calendar.getInstance().getTime()); 
				  }
			  }
			  else{
				  s_logger.info("Saml Assertion Signature is not valid");
			  }
			  
			  
		  }
		  
	  }
	  
	  
	  bcbsSamlProfileData.setDestinationUrl(samlResponse.getDestination());
		 
	  return bcbsSamlProfileData;
	 }
	
	
	
    private boolean isDateValid(Date notBefore, Date notOnOrAfter)
    {
    	Calendar c = Calendar.getInstance();
    	Date currentDate = c.getTime();

    	//return (currentDate.compareTo(notBefore) >= 0) && currentDate.before(notOnOrAfter);
    	return currentDate.before(notOnOrAfter);
	}



	public SamlProps getSamlProps() {
		return samlProps;
	}



	public void setSamlProps(SamlProps samlProps) {
		this.samlProps = samlProps;
	}



	public CryptoXml getCryptoXml() {
		return cryptoXml;
	}



	public void setCryptoXml(CryptoXml cryptoXml) {
		this.cryptoXml = cryptoXml;
	}
	
	/*
	 * This method extracts certificate from Pre configured certificate.
	 */
	public boolean isValidSamlAssertionSignature(Assertion assertion , SamlProps props) throws CustomSAMLException
	{
	

	  boolean isValidated = false;
	  
	  if (assertion.getDOM() != null) 
	  {
		    assertion.getDOM().setIdAttributeNS(null, "ID", true);
	  }

	  
		/*KeyStore keystore = KeystoreUtil.getKeyStore(props.getKeystore(), props.getKeystorePass().toCharArray());
		X509Certificate certificate = (X509Certificate) KeystoreUtil.getCertificateFromKeyStore(keystore, props.getKeystoreAlias());
		*/
		KeyStore keystore = KeystoreUtil.getKeyStore(props.getPartnerKeystore(), props.getPartnerKeystorePass().toCharArray());
		X509Certificate certificate = (X509Certificate) KeystoreUtil.getCertificateFromKeyStore(keystore, props.getPartnerKeystoreAlias());
		
		
		 X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(certificate.getPublicKey().getEncoded());
		 KeyFactory keyFactory;
		 if( assertion.isSigned()){
			 try {
					keyFactory = KeyFactory.getInstance("RSA");
				
				 BasicX509Credential publicCredential = new BasicX509Credential();
				 PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
				 publicCredential.setPublicKey(publicKey);
				 
				 SAMLSignatureProfileValidator signProfileValidator = new SAMLSignatureProfileValidator();
				 signProfileValidator.validate(assertion.getSignature());

				 
				 SignatureValidator signatureValidator = new SignatureValidator(publicCredential);
				 signatureValidator.validate(assertion.getSignature());
				
				 isValidated = true;
				 
				}catch(Exception ex)
				{
					//TODO
					ex.printStackTrace();
					s_logger.error("Exception Occured while validating Assertion Signature ", ex );
					  isValidated = false;
					
				}
		  }
		 else {
			
		}
		
		return isValidated;
	}
	

	/*
	 * This method extracts certificate from Pre configured certificate.
	 */
	public boolean isValidSamlResponseSignature(Response samlResponse , SamlProps props) throws CustomSAMLException
	{
	

	  boolean isValidated = false;
	  
	  if(!isValidSignatureProfile(samlResponse))
	  {
		  return false;
	  }

//		SecurityConfiguration securityConfiguration = 
//				(SecurityConfiguration)SpringContext.getBean(SecurityConfiguration.class);
//			
//		Map keyPairs = securityConfiguration.getKeyPairs();
//		KeyPairProperties validateCert = (KeyPairProperties) keyPairs.get(keyName);
	  
		KeyStore keystore = KeystoreUtil.getKeyStore(props.getKeystore(), props.getKeystorePass().toCharArray());
		X509Certificate certificate = (X509Certificate) KeystoreUtil.getCertificateFromKeyStore(keystore, props.getKeystoreAlias());
		
		
		 X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(certificate.getPublicKey().getEncoded());
		 KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		
		 BasicX509Credential publicCredential = new BasicX509Credential();
		 PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		 publicCredential.setPublicKey(publicKey);
		 
		 
		 SignatureValidator signatureValidator = new SignatureValidator(publicCredential);
		 
		 
		 Signature signature = samlResponse.getSignature();
		 
		  signatureValidator.validate(signature);
		  isValidated = true;
		}catch(Exception ex)
		{
			//TODO
			ex.printStackTrace();
			s_logger.error("Exception Occured while validating Assertion Signature ", ex );
			  isValidated = false;
			
		}
		return isValidated;
	}
	
	
	private static boolean isValidSignatureProfile(Response samlResponse)
	{
		boolean validResposne = false;
		SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();  
	try {
	    profileValidator.validate(samlResponse.getSignature());
	    validResposne = true;
	} catch (ValidationException e) {
	    // Indicates signature did not conform to SAML Signature profile
		s_logger.error("  SAML signature is not valid   ");
	    e.printStackTrace();
	    validResposne = false;
	}
			return validResposne;
	}
}
