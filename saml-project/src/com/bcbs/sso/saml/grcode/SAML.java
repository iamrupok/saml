package com.bcbs.sso.saml.grcode;

import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Map;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 * Base Class for SAML related classes.
 * 
 * @author sshaik
 */

public class SAML 
{

	//private String issuerURL;
	private static Log logger = LogFactory.getLog(SAML.class);
	
	static SecureRandomIdentifierGenerator generator;
	static final String SUBJECT_CONFIRMATION_PREFIX = "urn:oasis:names:tc:SAML:2.0:cm:";
	static final String ISSUER_FORMAT_PREFIX= "urn:oasis:names:tc:SAML:2.0:";
	static final String NAMEID_FORMAT_PREFIX= "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";//"urn:oasis:names:tc:SAML:1.1:nameid-format:"; /* 1.1 is correct in name id for SAML 2 version. */
	static final String AUTH_CLASS_REF_PREFIX="urn:oasis:names:tc:SAML:2.0:ac:classes:";
	
	
	static final String NAME_QUALIFIER_PREFIX ="urn:saml20:bcbsnc:idp:preprod";
	static final String SPNameQualifer ="urn:saml20:epsilon:sp:preprod";
	static final String Service_Provider_URL = "http://dmawbicobo01.bico.edm:8080/BOE/BI/custom.jsp";
	
	/**
	 * Static block to make sure the OpenSAML bootstrap. Also, initializing the
	 * generator which comes as handy.
	 */

	static {
		try {
			DefaultBootstrap.bootstrap();
			generator = new SecureRandomIdentifierGenerator();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public DocumentBuilder getDocumentBuilder()
			throws ParserConfigurationException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		return factory.newDocumentBuilder();
	}

	/**
	 * Helper method to create objects using OpenSAML builder.
	 */

	@SuppressWarnings("unchecked")
	public <T> T create(Class<T> clazz, QName qname) {
		return (T) ((XMLObjectBuilder) Configuration.getBuilderFactory()
				.getBuilder(qname)).buildObject(qname);
	}

	/**
	 * Helper method to add an XMLObject as a child of a DOM Element.
	 */
	public static Element addToElement(XMLObject object, Element parent)
			throws IOException, MarshallingException, TransformerException {
		Marshaller out = Configuration.getMarshallerFactory().getMarshaller(
				object);
		return out.marshall(object, parent);
	}

	/**
	 * Helper method to get an XMLObject as a DOM Document.
	 * 
	 * @throws ParserConfigurationException
	 */
	public Document asDOMDocument(XMLObject object) throws IOException,
			MarshallingException, TransformerException,
			ParserConfigurationException {
		Document document = getDocumentBuilder().newDocument();
		Marshaller out = Configuration.getMarshallerFactory().getMarshaller(
				object);
		out.marshall(object, document);
		return document;
	}

	/**
	 * Helper method to get plain String from XMLObject or Assertion.
	 * 
	 * @throws ParserConfigurationException
	 */
	public String getAsPlainString(XMLObject object) throws IOException,
			MarshallingException, TransformerException,
			ParserConfigurationException {
		Document document = getDocumentBuilder().newDocument();
		Marshaller out = Configuration.getMarshallerFactory().getMarshaller(
				object);
		Element element = out.marshall(object, document);
		return XMLHelper.nodeToString(element);

	}

	/**
	 * Helper method to print any XML object to a file.
	 * 
	 * @throws ParserConfigurationException
	 */
	public void printToFile(XMLObject object, String filename)
			throws IOException, MarshallingException, TransformerException,
			ParserConfigurationException {
		String result = getAsPlainString(object);
		if (filename != null) {
			PrintWriter writer = new PrintWriter(new FileWriter(filename));
			writer.println(result);
			writer.close();
		} else{
			//logger.debug(result);
		}
	}

	/**
	 * Helper method to read an XML object from a DOM element.
	 */
	public static XMLObject fromElement(Element element) throws IOException,
			UnmarshallingException, SAXException {
		return Configuration.getUnmarshallerFactory().getUnmarshaller(element)
				.unmarshall(element);
	}

	



	/**
	 * Helper method to get SMAL Subject object.
	 */
	public Subject createSubject(SAMLData samlData) {
		NameID nameID = create(NameID.class, NameID.DEFAULT_ELEMENT_NAME);
		nameID.setValue(samlData.getNameValue());
		if (samlData.getNameIdFormat() != null)
			nameID.setFormat(NAMEID_FORMAT_PREFIX+samlData.getNameIdFormat());
		else
			nameID.setFormat(NameID.UNSPECIFIED);

		Subject subject = create(Subject.class, Subject.DEFAULT_ELEMENT_NAME);
		subject.setNameID(nameID);


			SubjectConfirmation subjectConfirmation = create(
					SubjectConfirmation.class,
					SubjectConfirmation.DEFAULT_ELEMENT_NAME);
			subjectConfirmation.setMethod(SUBJECT_CONFIRMATION_PREFIX + ( null != samlData.getSubjectConfirmationMethod()
					? samlData.getSubjectConfirmationMethod() : "bearer") );


			
			SubjectConfirmationData subjectConfirmationData = create(SubjectConfirmationData.class,
					SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
			subjectConfirmationData.setInResponseTo(null != samlData.getInReponseTo() ? 
					samlData.getInReponseTo() : null);
			DateTime now = new DateTime();
			subjectConfirmationData.setNotOnOrAfter(now.plusMinutes(2));
			subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
			subjectConfirmationData.setRecipient(samlData.getReceipientUrl());
			subject.getSubjectConfirmations().add(subjectConfirmation);
			
			

		return subject;
	}

	/**
	 * Returns a SAML assertion with generated ID, current timestamp, given
	 * subject, and simple time-based conditions.
	 * 
	 * @param subject
	 *            Subject of the assertion
	 */
	public Assertion createAssertion(Subject subject, int notbefore,
			int notafter) {
		Assertion assertion = create(Assertion.class,
				Assertion.DEFAULT_ELEMENT_NAME);
		assertion.setID(generator.generateIdentifier());

		DateTime now = new DateTime();
		assertion.setIssueInstant(now);

		/*if (issuerURL != null)
			assertion.setIssuer(spawnIssuer());*/

		assertion.setSubject(subject);

		Conditions conditions = create(Conditions.class,
				Conditions.DEFAULT_ELEMENT_NAME);
		conditions.setNotBefore(now.minusSeconds(10));
		conditions.setNotOnOrAfter(now.plusMinutes(2));
		assertion.setConditions(conditions);

		return assertion;
	}

	/**
	 * Helper method to generate a response, based on a pre-built assertion.
	 */
	public Response createResponse(Assertion assertion) throws IOException,
			MarshallingException, TransformerException {
		return createResponse(assertion, null);
	}

	/**
	 * Helper method to generate a shell response with a given status code and
	 * and in responseTo String.
	 */
	public Response createResponse(String statusCode, String inResponseTo, String destination)
			throws IOException, MarshallingException, TransformerException {
		return createResponse(statusCode, null, inResponseTo, destination);
	}

	/**
	 * Helper method to generate a shell response with a given status code,
	 * status message, and query ID.
	 */
	public Response createResponse(String statusCode, String message,
			String inResponseTo, String destination) throws IOException, MarshallingException,
			TransformerException {
		Response response = create(Response.class,
				Response.DEFAULT_ELEMENT_NAME);
		response.setID(generator.generateIdentifier());

		if (inResponseTo != null)
			response.setInResponseTo(inResponseTo);
		
		if (destination != null)
			response.setDestination(destination);
		

		DateTime now = new DateTime();
		response.setIssueInstant(now);
/*
		if (issuerURL != null)
			response.setIssuer(spawnIssuer());*/

		StatusCode statusCodeElement = create(StatusCode.class,
				StatusCode.DEFAULT_ELEMENT_NAME);
		statusCodeElement.setValue(statusCode);

		Status status = create(Status.class, Status.DEFAULT_ELEMENT_NAME);
		status.setStatusCode(statusCodeElement);
		response.setStatus(status);

		if (message != null) {
			StatusMessage statusMessage = create(StatusMessage.class,
					StatusMessage.DEFAULT_ELEMENT_NAME);
			statusMessage.setMessage(message);
			status.setStatusMessage(statusMessage);
		}

		return response;
	}


	
	/**
	 * Helper method to generate a response, based on a pre-built assertion and
	 * query ID.
	 */
	public Response createResponse(Assertion assertion, String inResponseTo)
			throws IOException, MarshallingException, TransformerException {
		Response response = createResponse(StatusCode.SUCCESS_URI, inResponseTo, null);

		response.getAssertions().add(assertion);
		return response;
	}
	
	/**
	 * Helper method to generate a response, based on a pre-built assertion and
	 * query ID.
	 */
	public Response createResponse(Assertion assertion, String inResponseTo, String destination)
			throws IOException, MarshallingException, TransformerException {
		Response response = createResponse(StatusCode.SUCCESS_URI, inResponseTo, destination);

		response.getAssertions().add(assertion);
		return response;
	}


	
	public Assertion createAuthnAssertion(Subject subject, String authnCtx) {
		Assertion assertion = createAssertion(subject, 10, 10);

		AuthnContextClassRef ref = create(AuthnContextClassRef.class,
				AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		ref.setAuthnContextClassRef(authnCtx);

		AuthnContext authnContext = create(AuthnContext.class,
				AuthnContext.DEFAULT_ELEMENT_NAME);
		authnContext.setAuthnContextClassRef(ref);

		AuthnStatement authnStatement = create(AuthnStatement.class,
				AuthnStatement.DEFAULT_ELEMENT_NAME);
		authnStatement.setAuthnContext(authnContext);

		assertion.getStatements().add(authnStatement);

		return assertion;
	}

	/**
	 * Adds a SAML attribute to an attribute statement with XSString type.
	 * 
	 * @param statement
	 *            Existing AttributeStatement
	 * @param name
	 *            Attribute name
	 * @param value
	 *            Attribute value
	 */
	public void addAttribute(AttributeStatement statement, String name,
			String value) {

		final XMLObjectBuilder builder = Configuration.getBuilderFactory().getBuilder(XSString.TYPE_NAME);

		SAMLObjectBuilder<Attribute> attrBuilder = (SAMLObjectBuilder<Attribute>) Configuration
				.getBuilderFactory().getBuilder(Attribute.DEFAULT_ELEMENT_NAME);

		Attribute attribute = attrBuilder.buildObject();
		attribute.setName(name);

		XMLObjectBuilder stringBuilder = Configuration.getBuilderFactory()
				.getBuilder(XSString.TYPE_NAME);
		XSString attrNewValue = (XSString) stringBuilder.buildObject(
				AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		attrNewValue.setValue(value);

		attribute.getAttributeValues().add(attrNewValue);
		statement.getAttributes().add(attribute);
	}
	
	/**
	 * Adds a SAML attribute to an attribute statement with XSAny type.
	 * 
	 * @param statement
	 *            Existing AttributeStatement
	 * @param name
	 *            Attribute name
	 * @param value
	 *            Attribute value
	 */
	
	public void addXSAnyAttribute(AttributeStatement statement, String name,
			String value) {

		final XMLObjectBuilder builder = Configuration.getBuilderFactory().getBuilder(XSAny.TYPE_NAME);

		SAMLObjectBuilder<Attribute> attrBuilder = (SAMLObjectBuilder<Attribute>) Configuration
				.getBuilderFactory().getBuilder(Attribute.DEFAULT_ELEMENT_NAME);

		Attribute attribute = attrBuilder.buildObject();
		attribute.setName(name);

		XMLObjectBuilder objectBuilder = Configuration.getBuilderFactory()
				.getBuilder(XSAny.TYPE_NAME);
		XSAny attrNewValue = (XSAny) objectBuilder.buildObject(
				AttributeValue.DEFAULT_ELEMENT_NAME, XSAny.TYPE_NAME);
		attrNewValue.setTextContent(value);

		attribute.getAttributeValues().add(attrNewValue);
		statement.getAttributes().add(attribute);
	}

	public AttributeStatement addAttributes(Map<String, String> attributes) {

		AttributeStatement statement = create(AttributeStatement.class,
				AttributeStatement.DEFAULT_ELEMENT_NAME);
		if (attributes != null)
			for (Map.Entry<String, String> entry : attributes.entrySet())
				addAttribute(statement, entry.getKey(), entry.getValue());

		return statement;

	}

	/**
	 * Returns a SAML attribute assertion.
	 * 
	 * @param subject
	 *            Subject of the assertion
	 * @param attributes
	 *            Attributes to be stated (may be null)
	 */
	public Assertion createAttributeAssertion(Subject subject,
			Map<String, String> attributes) {
		Assertion assertion = createAssertion(subject, 10, 10);

		AttributeStatement statement = create(AttributeStatement.class,
				AttributeStatement.DEFAULT_ELEMENT_NAME);
		if (attributes != null)
			for (Map.Entry<String, String> entry : attributes.entrySet())
				addAttribute(statement, entry.getKey(), entry.getValue());

		assertion.getStatements().add(statement);

		return assertion;
	}
	
	/**
    	Helper method to to sign Assertion	
    */
	public void signResponse(Response response, KeyStore.PrivateKeyEntry privateKeyEntry) 
	{
		
		logger.debug(" --------------------- Signing start ------------- ");
		
		//Assertion assertion = response.getAssertions().get(0);
		
		Signature signature = null;
		signature = (Signature) Configuration.getBuilderFactory()
				.getBuilder(Signature.DEFAULT_ELEMENT_NAME)
				.buildObject(Signature.DEFAULT_ELEMENT_NAME);
		
	
		PrivateKey privateKey = privateKeyEntry.getPrivateKey();
		
		//logger.debug("PrivateKey Details  \n " + privateKey.toString());
		X509Certificate x509Certificate =(X509Certificate) privateKeyEntry.getCertificate();
		

		
		BasicX509Credential credential = new BasicX509Credential();
		
		credential.setEntityCertificate(x509Certificate);
		credential.setPrivateKey(privateKey);
		Credential signingCredential  = credential;
		

		
		signature.setSigningCredential(signingCredential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		String keyInfoGeneratorProfile = "XMLSignature";
		
		
		
		
		SecurityConfiguration securityConfiguration = Configuration
						.getGlobalSecurityConfiguration();
		
		try {
			SecurityHelper.prepareSignatureParams(signature, signingCredential,
					securityConfiguration, null);
		} catch (org.opensaml.xml.security.SecurityException e) {	
			logger.error("Security Excepton   ------> " + e.getMessage());
			e.printStackTrace();
		}
		//assertion.setSignature(signature);
		for  (int i=0; i<response.getAssertions().size();i++)
		{
			//response.getAssertions().get(i).setSignature(signature);
			response.setSignature(signature);
			
		}
		
		//response.setSignature(signature);
		
		
		try {
			Configuration.getMarshallerFactory().getMarshaller(response)
					.marshall(response);
		} catch (MarshallingException e) {
			e.printStackTrace();
		}
		
		try {
			Signer.signObject(signature);
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		
		
		if(logger.isDebugEnabled())
		{
			try{
			ResponseMarshaller marshaller = new ResponseMarshaller();
			Element plain = marshaller.marshall(response);
			
			String samlResponse = XMLHelper.nodeToString(plain);
			//logger.debug("********************\n*\n***********::" + samlResponse);
			}catch(Exception e)
			{
				e.printStackTrace();
			}
			
		}
		
	}
	
	
	public Assertion signAssertionNew(Assertion assertion, KeyStore.PrivateKeyEntry privateKeyEntry) 
	{
		
		logger.debug(" --------------------- Signing start ------------- ");
		
		//Assertion assertion = response.getAssertions().get(0);
		
		Signature signature = null;
		String samlAssertion = "";
		signature = (Signature) Configuration.getBuilderFactory()
				.getBuilder(Signature.DEFAULT_ELEMENT_NAME)
				.buildObject(Signature.DEFAULT_ELEMENT_NAME);
		
	
		PrivateKey privateKey = privateKeyEntry.getPrivateKey();
		
		//logger.debug("PrivateKey Details  \n " + privateKey.toString());
		X509Certificate x509Certificate =(X509Certificate) privateKeyEntry.getCertificate();
		

		
		BasicX509Credential credential = new BasicX509Credential();
		
		credential.setEntityCertificate(x509Certificate);
		credential.setPrivateKey(privateKey);
		Credential signingCredential  = credential;
		
		
		
		signature.setSigningCredential(signingCredential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		String keyInfoGeneratorProfile = "XMLSignature";
	
		
		
		
		SecurityConfiguration securityConfiguration = Configuration
						.getGlobalSecurityConfiguration();
		
		try {
			SecurityHelper.prepareSignatureParams(signature, signingCredential,
					securityConfiguration, null);
		} catch (org.opensaml.xml.security.SecurityException e) {	
			logger.error("Security Excepton   ------> " + e.getMessage());
			e.printStackTrace();
		}
		assertion.setSignature(signature);
	
		//response.setSignature(signature);
		
		try {
			Configuration.getMarshallerFactory().getMarshaller(assertion)
					.marshall(assertion);
		} catch (MarshallingException e) {
			e.printStackTrace();
		}
		
		try {
			Signer.signObject(signature);
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		
		if(logger.isDebugEnabled())
		{
			try{
			ResponseMarshaller marshaller = new ResponseMarshaller();
			Element plain = marshaller.marshall(assertion);
			
			 samlAssertion = XMLHelper.nodeToString(plain);
			logger.debug("********************\n*\n***********::" + samlAssertion);
			}catch(Exception e)
			{
				e.printStackTrace();
			}
			
		}
		return assertion;
		
	}
	public String signAssertion(Assertion assertion, KeyStore.PrivateKeyEntry privateKeyEntry) 
	{
		
		logger.debug(" --------------------- Signing start ------------- ");
		
		//Assertion assertion = response.getAssertions().get(0);
		
		Signature signature = null;
		String samlAssertion = "";
		signature = (Signature) Configuration.getBuilderFactory()
				.getBuilder(Signature.DEFAULT_ELEMENT_NAME)
				.buildObject(Signature.DEFAULT_ELEMENT_NAME);
		
	
		PrivateKey privateKey = privateKeyEntry.getPrivateKey();
		
		//logger.debug("PrivateKey Details  \n " + privateKey.toString());
		X509Certificate x509Certificate =(X509Certificate) privateKeyEntry.getCertificate();
		

		
		BasicX509Credential credential = new BasicX509Credential();
		
		credential.setEntityCertificate(x509Certificate);
		credential.setPrivateKey(privateKey);
		Credential signingCredential  = credential;
		

		
		signature.setSigningCredential(signingCredential);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		String keyInfoGeneratorProfile = "XMLSignature";
		
		
		
		
		SecurityConfiguration securityConfiguration = Configuration
						.getGlobalSecurityConfiguration();
		
		try {
			SecurityHelper.prepareSignatureParams(signature, signingCredential,
					securityConfiguration, null);
		} catch (org.opensaml.xml.security.SecurityException e) {	
			logger.error("Security Excepton   ------> " + e.getMessage());
			e.printStackTrace();
		}
		assertion.setSignature(signature);
		//response.setSignature(signature);
		
		try {
			Configuration.getMarshallerFactory().getMarshaller(assertion)
					.marshall(assertion);
		} catch (MarshallingException e) {
			e.printStackTrace();
		}
		
		try {
			Signer.signObject(signature);
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		
		if(logger.isDebugEnabled())
		{
			try{
			ResponseMarshaller marshaller = new ResponseMarshaller();
			Element plain = marshaller.marshall(assertion);
			
			 samlAssertion = XMLHelper.nodeToString(plain);
			logger.debug("********************\n*\n***********::" + samlAssertion);
			}catch(Exception e)
			{
				e.printStackTrace();
			}
			
		}
		return samlAssertion;
		
	}
	
	/*
	 * Helper method to get SAML Response from Plain XML String
	 *  @param plainString
	 */
	
	public Response getResponse(String plainString) throws CustomSAMLException
	{
		Document document = null;
		 Response samlResponse = null;
		 
		 if(null == plainString || plainString.trim().length() == 0)
		 {
			 throw new CustomSAMLException("Empty Response String received. Aborting String parsing");
		 }
		
	     ByteArrayInputStream is = new ByteArrayInputStream(plainString.getBytes());
         
         DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
         documentBuilderFactory.setNamespaceAware(true);
         
         DocumentBuilder docBuilder;
		try {
			docBuilder = documentBuilderFactory.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
		
			e.printStackTrace();
			logger.error(" Error while creatign document builder ");
			throw  new CustomSAMLException("ParserConfigurationException while creating docBuilder ");
		}

         
		try {
			document = docBuilder.parse(is);
		} catch (SAXException e) {
			e.printStackTrace();
			logger.error("SAXException whiel parsing input stream ",e);
			throw new CustomSAMLException("SAXException whiel parsing input stream ");
		} catch (IOException e) {
			e.printStackTrace();
			logger.error("IOException whiel parsing input stream ",e);
			throw new CustomSAMLException("IOException whiel parsing input stream ");
		}
         Element element = document.getDocumentElement();
         
         
         UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
         Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
         XMLObject responseXmlObj;
		try {
			responseXmlObj = unmarshaller.unmarshall(element);
		} catch (UnmarshallingException e) {
			e.printStackTrace();
			logger.error("UnmarshallingException whiel unarshalling element",e);
			throw new CustomSAMLException("UnmarshallingException whiel unarshalling element ");
		}
         
         
         samlResponse = (Response) responseXmlObj;
         
         return samlResponse;
         }
	
	
	
	/*
	 *  Helper method to get the custom Attributes in form of Map<String, String> from
	 *  SAML Response.
	 *  This method is intended to use when partner receive the SAML Response and get only
	 *  Attributes out of response for further processing.
	 */
//	 public Map<String, String> getCustomattributesMap(Response samlResponse) throws CustomSAMLException
//	 {
//		 
//		 List<Attribute> customAttributes = new ArrayList<Attribute>();
//		   Assertion assertion = samlResponse.getAssertions().get(0);
//	          List<AttributeStatement> attributeStatements =   assertion.getAttributeStatements();
//	          Map<String, String> customAttriburesMap = new HashMap<String, String>();
//	          customAttributes =   attributeStatements.get(0).getAttributes();
//	          
//	          for(Attribute tempAttribute : customAttributes)
//        	  {
//        		 //String attributeName =  tempAttribute.getName();
//        		  String attributeName  =   tempAttribute.getDOM().getAttribute("Name");
//        		  
//        		  attributeName = null == attributeName ? "": attributeName;
//        		  
//        		  logger.debug("Attribute name --------> " +attributeName );
//        		 List<XMLObject> xmlObjectValues = tempAttribute.getAttributeValues();
//        		 XMLObject xmlObject =    xmlObjectValues.get(0);
//        		 
//        		 String strAttributeValue = xmlObject.getDOM().getTextContent();
//        		 
//        		 strAttributeValue =  null == strAttributeValue ? "" : strAttributeValue;
//        		 logger.debug("Attribute value  --------> " +strAttributeValue );
//        		 
//        		 customAttriburesMap.put(attributeName, strAttributeValue);
//        		}
//	     return customAttriburesMap;
//		 
//	 }
	
	}
