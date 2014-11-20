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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.log4j.Logger;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallerFactory;

import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.bcbs.sso.common.saml.authentication.SamlProps;
import com.bcbs.sso.common.saml.model.SamlProfileData;
import com.bcbs.sso.saml.grcode.KeystoreUtil;



public class PortalSaml {
	// protected final Log s_logger = LogFactory.getLog(BcbsPortalSaml.class);
	static Logger s_logger = Logger.getLogger(PortalSaml.class);

	public SamlProps samlProps;
	public CryptoXml cryptoXml;

	public static final String DEFAULT_ORIGINATOR = "BCBSLOGIN";

	public boolean isValidAssertionSignature(Assertion assertion, SamlProps props)
		
	{
		
		 if (assertion.getDOM() != null) {
			 assertion.getDOM().setIdAttributeNS(null, "ID", true);
         } 

		boolean isValidated = false;
		//KeyStore keystore = KeystoreUtil.getKeyStore(props.getKeystore(), props.getKeystorePass().toCharArray());
		KeyStore keystore = KeystoreUtil.getKeyStore(props.getPartnerKeystore(), props
				.getPartnerKeystorePass().toCharArray());

		X509Certificate certificate = (X509Certificate) KeystoreUtil
				.getCertificateFromKeyStore(keystore, props.getPartnerKeystoreAlias());

		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(certificate
				.getPublicKey().getEncoded());

		KeyFactory keyFactory;
		 

		try {

			keyFactory = KeyFactory.getInstance("RSA");

			BasicX509Credential publicCredential = new BasicX509Credential();

			PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

			publicCredential.setPublicKey(publicKey);

			SignatureValidator signatureValidator = new SignatureValidator(
					publicCredential);
			
			Signature signature = assertion.getSignature();

			signatureValidator.validate(signature);

			isValidated = true;

		} catch (Exception nae)

		{
			// TODO

			nae.printStackTrace();
			s_logger.error("Signature is not valid ", nae);
			isValidated = false;		

		} 
		return isValidated;

	}

	
	public boolean isValidResponseSignature(Response samlResponse, SamlProps props)
	
	{

		boolean isValidated = false;
		KeyStore keystore = KeystoreUtil.getKeyStore(props.getPartnerKeystore(), props
				.getPartnerKeystorePass().toCharArray());

		X509Certificate certificate = (X509Certificate) KeystoreUtil
				.getCertificateFromKeyStore(keystore, props.getPartnerKeystoreAlias());

		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(certificate
				.getPublicKey().getEncoded());

		KeyFactory keyFactory;
		 

		try {

			keyFactory = KeyFactory.getInstance("RSA");

			BasicX509Credential publicCredential = new BasicX509Credential();

			PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

			publicCredential.setPublicKey(publicKey);

			SignatureValidator signatureValidator = new SignatureValidator(
					publicCredential);
			
			Signature signature = samlResponse.getSignature();

			signatureValidator.validate(signature);

			isValidated = true;

		} catch (Exception nae)

		{
			// TODO

			nae.printStackTrace();
			s_logger.error("Signature is not valid ", nae);
			isValidated = false;		

		} 
		return isValidated;

	}
	public SamlProfileData processLoginResponseSAML2(
			String loginSAMLResponse) throws Exception {

		String strSamlResponse = cryptoXml.decrypt(loginSAMLResponse);
		SamlProfileData bcbsSamlProfileData = new SamlProfileData();
		ByteArrayInputStream is = new ByteArrayInputStream(
				strSamlResponse.getBytes());
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder docBuilder = documentBuilderFactory
				.newDocumentBuilder();

		Document document = docBuilder.parse(is);
		Element element = document.getDocumentElement();

		UnmarshallerFactory unmarshallerFactory = org.opensaml.Configuration
				.getUnmarshallerFactory();
		org.opensaml.xml.io.Unmarshaller unmarshaller = unmarshallerFactory
				.getUnmarshaller(element);
		XMLObject responseXmlObj = unmarshaller.unmarshall(element);

		Response samlResponse = (Response) responseXmlObj;
	
		/*
		 * Signature sig = samlResponse.getSignature(); // Validating the
		 * signature SignatureValidator validator = new
		 * SignatureValidator(credential); validator.validate(sig);
		 */
		/************************** Print the Response as XML String *****************************************/

		ResponseMarshaller marshaller = new ResponseMarshaller();
		Element plain;
		String response = null;
		try {
			plain = marshaller.marshall(samlResponse);
			response = XMLHelper.nodeToString(plain);
			s_logger.info("Received Response: " + response);
			System.out.println("Received Response: " + response);
		} catch (MarshallingException e) {
			e.printStackTrace();
		}

		if (samlResponse != null) { // response.verify(certificate);

			if (samlResponse.getAssertions().iterator().hasNext()) {

				Assertion assertion = (Assertion) samlResponse.getAssertions()
						.iterator().next();
				// assertion.checkValidity();
				//Checked key store
				if(isValidAssertionSignature(assertion,getSamlProps())){
					s_logger.info("Assertion Signature is valid");
					org.joda.time.DateTime notB = assertion.getConditions()
							.getNotBefore();
					org.joda.time.DateTime notOnOrA = assertion.getConditions()
							.getNotOnOrAfter();

					Date notBefore = notB.toDate();
					Date notOnOrAfter = notOnOrA.toDate();

					if (isDateValid(notBefore, notOnOrAfter)) {
					
						Iterator aserItr = assertion.getStatements().iterator();
						if (aserItr.hasNext()) {
							AuthnStatement statement = (AuthnStatement) aserItr
									.next();
						}
						if (aserItr.hasNext()) {
							AttributeStatement attribStmt = (AttributeStatement) aserItr
									.next();

							Iterator attribItr = attribStmt.getAttributes()
									.iterator();

							while (attribItr.hasNext()) {
								Attribute samlAttr = (Attribute) attribItr.next();
								if (samlAttr.getName() != null
										&& samlAttr.getName().equals("userId")) {
									XMLObject obj = samlAttr.getAttributeValues()
											.get(0);
									if (obj != null) {
										bcbsSamlProfileData.setUserId(obj.getDOM()
												.getTextContent());
										
									}
								}
								if (samlAttr.getName() != null
										&& samlAttr.getName().equals("secretKey")) {
									XMLObject obj = samlAttr.getAttributeValues()
											.get(0);
									if (obj != null) {
										bcbsSamlProfileData.setSecretKey(obj
												.getDOM().getTextContent());
										
									}
								}
							}
						}

					} else {
						s_logger.error("SAML Response expired. notBefore: "
								+ notBefore + "   notOnOrAfter: " + notOnOrAfter
								+ "     current time: "
								+ Calendar.getInstance().getTime());
					}
				}
				else{
					
					s_logger.error("Assertion Signature is invalid");
				}
				
				
			}

		}

		return bcbsSamlProfileData;
	}

	private boolean isDateValid(Date notBefore, Date notOnOrAfter) {
		Calendar c = Calendar.getInstance();
		Date currentDate = c.getTime();
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

}
