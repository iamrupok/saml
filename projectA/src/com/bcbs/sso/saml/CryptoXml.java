package com.bcbs.sso.saml;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.KeyGenerator;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.utils.EncryptionConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import com.bcbs.sso.common.saml.app.security.CryptoException;
import com.bcbs.sso.common.saml.authentication.SamlProps;
import com.bcbs.sso.common.saml.misc.CryptoKeystoreUtil;
import com.bcbs.sso.saml.BcbsLoginProps;
import com.bcbs.sso.saml.grcode.InitializeSAMLData;

/**
 * @author Srinivas Purma
 */
public class CryptoXml
{
    public BcbsLoginProps m_samlProps;
    private static Log s_logger = LogFactory.getLog(InitializeSAMLData.class);

    static
    {
    	org.apache.xml.security.Init.init();
    }

    /* (non-Javadoc)
     * @see com.frequencymarketing.common.app.security.Encryption#encrypt(java.lang.String)
     */
    
       
    public static String encryptPartner(String a_text,SamlProps props) throws CryptoException, Exception
    {
    	javax.xml.parsers.DocumentBuilderFactory dbf =	javax.xml.parsers.DocumentBuilderFactory.newInstance();
    	dbf.setNamespaceAware(true);
    	javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
    	Document doc = db.parse(new ByteArrayInputStream(a_text.getBytes()));

    	KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    	keyGenerator.init(128);
    	Key symmetricKey = keyGenerator.generateKey();
    	s_logger.debug("\n\n\n Keystore Value :--> " + props.getPartnerKeystore() + "    Pass:  " + props.getPartnerKeystorePass().toCharArray());
        KeyStore keystore = CryptoKeystoreUtil.getKeyStore(props
                .getPartnerKeystore(), props.getPartnerKeystorePass().toCharArray());
        
        //KeyPair  keypair  = CryptoKeystoreUtil.getKeyPair(keystore, props.getPartnerKeystoreAlias(), props.getPartnerKeystorePass().toCharArray());
        //PublicKey publicKey = keystore.getCertificate("idp").getPublicKey();
        PublicKey publicKey = CryptoKeystoreUtil.getCertificateFromKeyStore(keystore,  props.getPartnerKeystoreAlias()).getPublicKey();
        //PublicKey publicKey = keypair.getPublic();
    	String algorithmURI = XMLCipher.RSA_v1dot5;

    	XMLCipher keyCipher =
    	XMLCipher.getInstance(algorithmURI);
    	keyCipher.init(XMLCipher.WRAP_MODE, publicKey);
    	EncryptedKey encryptedKey =
    	keyCipher.encryptKey(doc, symmetricKey);

    	Element rootElement = doc.getDocumentElement();
    	algorithmURI = XMLCipher.AES_128;
    	XMLCipher xmlCipher =
    	XMLCipher.getInstance(algorithmURI);
    	xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);

    	EncryptedData encryptedData = xmlCipher.getEncryptedData();
    	KeyInfo keyInfo = new KeyInfo(doc);
    	keyInfo.add(encryptedKey);
    	encryptedData.setKeyInfo(keyInfo);

    	xmlCipher.doFinal(doc, rootElement, false);

    	BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encodeBuffer(convertDocumentToString(doc).getBytes());
    }


    private static String convertDocumentToString(Document doc) throws Exception
    {
    	String strDoc = null;
    	StringWriter sw = new StringWriter();
    	TransformerFactory factory = TransformerFactory.newInstance();
    	Transformer transformer = factory.newTransformer();
    	transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
    	DOMSource source = new DOMSource(doc);
    	StreamResult result = new StreamResult(sw);
    	transformer.transform(source, result);
    	strDoc = new String(sw.getBuffer().toString());
    	sw.close();

    	return strDoc;
    }
    /* (non-Javadoc)
     * @see com.frequencymarketing.common.app.security.Encryption#decrypt(java.lang.String)
     */
    
    public String decrypt(String a_encrypted) throws CryptoException, Exception
    {
    	
    	javax.xml.parsers.DocumentBuilderFactory dbf =	javax.xml.parsers.DocumentBuilderFactory.newInstance();
    	dbf.setNamespaceAware(true);
    	javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
    	BASE64Decoder decoder = new BASE64Decoder();

    	Document doc = db.parse(new ByteArrayInputStream(decoder.decodeBuffer(a_encrypted)));

    	Element encryptedDataElement =
    		(Element) doc.getElementsByTagNameNS(
    		EncryptionConstants.EncryptionSpecNS,
    		EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);

    	Element e = (Element)
    	doc.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS,
    	EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);
    	XMLCipher cipher = XMLCipher.getInstance();
    	cipher.init(XMLCipher.DECRYPT_MODE, null);

    	EncryptedData encryptedData = cipher.loadEncryptedData(doc, e);

    	if(encryptedData == null)
    	{
    	throw new Exception("EncryptedData is null");
    	}
    	else if (encryptedData.getKeyInfo() == null)
    	{
    	throw new Exception("KeyInfo of the EncryptedData is null");
    	}

    	// get private key from key store
        KeyStore keyStore = CryptoKeystoreUtil.getKeyStore(getSamlProps()
                .getKeystore(), getSamlProps().getKeystorePass().toCharArray());
        KeyPair  keypair  = CryptoKeystoreUtil.getKeyPair(keyStore, getSamlProps().getKeystoreAlias(), getSamlProps().getKeystorePass().toCharArray());
        //PrivateKey privateKey = (PrivateKey)keyStore.getKey("idp", props.getKeystorePass().toCharArray());
          PrivateKey privateKey = keypair.getPrivate();
      
          // get encrypted key data from document
    	EncryptedKey ek = encryptedData.getKeyInfo().itemEncryptedKey(0);
    	Key secretKey = null;
    	if (ek != null)
    	{
    		XMLCipher keyCipher = XMLCipher.getInstance();
    		keyCipher.init(XMLCipher.UNWRAP_MODE, privateKey);
    		secretKey = keyCipher.decryptKey(ek, encryptedData.getEncryptionMethod().getAlgorithm());
    	}
    	XMLCipher xmlCipher = XMLCipher.getInstance();
    	xmlCipher.init(XMLCipher.DECRYPT_MODE, secretKey);

    	xmlCipher.doFinal(doc, encryptedDataElement);

        return convertDocToString(doc);
    }

    private String convertDocToString(Document doc) throws Exception
    {
    	String strDoc = null;
    	StringWriter sw = new StringWriter();
    	TransformerFactory factory = TransformerFactory.newInstance();
    	Transformer transformer = factory.newTransformer();
    	transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
    	DOMSource source = new DOMSource(doc);
    	StreamResult result = new StreamResult(sw);
    	transformer.transform(source, result);
    	strDoc = new String(sw.getBuffer().toString());
    	sw.close();

    	return strDoc;
    }

    public BcbsLoginProps getSamlProps()
    {
        return m_samlProps;
    }

    public void setSamlProps(BcbsLoginProps a_samlProps)
    {
        m_samlProps = a_samlProps;
    }
    
    
    /* (non-Javadoc)
     * @see com.frequencymarketing.common.app.security.Encryption#decrypt(java.lang.String)
     */
    /*public static String decrypt(String a_encrypted,SamlProps props) throws CryptoException, Exception
    {
    	
    	javax.xml.parsers.DocumentBuilderFactory dbf =	javax.xml.parsers.DocumentBuilderFactory.newInstance();
    	dbf.setNamespaceAware(true);
    	javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
    	BASE64Decoder decoder = new BASE64Decoder();

    	Document doc = db.parse(new ByteArrayInputStream(decoder.decodeBuffer(a_encrypted)));

    	Element encryptedDataElement =
    		(Element) doc.getElementsByTagNameNS(
    		EncryptionConstants.EncryptionSpecNS,
    		EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);

    	Element e = (Element)
    	doc.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS,
    	EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);
    	XMLCipher cipher = XMLCipher.getInstance();
    	cipher.init(XMLCipher.DECRYPT_MODE, null);

    	EncryptedData encryptedData = cipher.loadEncryptedData(doc, e);

    	if(encryptedData == null)
    	{
    	throw new Exception("EncryptedData is null");
    	}
    	else if (encryptedData.getKeyInfo() == null)
    	{
    	throw new Exception("KeyInfo of the EncryptedData is null");
    	}

    	// get private key from key store
        KeyStore keyStore = CryptoKeystoreUtil.getKeyStore(props
                .getKeystore(), props.getKeystorePass().toCharArray());
    	
        KeyPair  keypair  = CryptoKeystoreUtil.getKeyPair(keyStore, props.getKeystoreAlias(), props.getKeystorePass().toCharArray());
      //PrivateKey privateKey = (PrivateKey)keyStore.getKey("idp", props.getKeystorePass().toCharArray());
        PrivateKey privateKey = keypair.getPrivate();
    	// get encrypted key data from document
    	EncryptedKey ek = encryptedData.getKeyInfo().itemEncryptedKey(0);
    	Key secretKey = null;
    	if (ek != null)
    	{
    		XMLCipher keyCipher = XMLCipher.getInstance();
    		keyCipher.init(XMLCipher.UNWRAP_MODE, privateKey);
    		secretKey = keyCipher.decryptKey(ek, encryptedData.getEncryptionMethod().getAlgorithm());
    	}
    	XMLCipher xmlCipher = XMLCipher.getInstance();
    	xmlCipher.init(XMLCipher.DECRYPT_MODE, secretKey);

    	xmlCipher.doFinal(doc, encryptedDataElement);

        return convertDocumentToString(doc);
    }
*/
    /*public static String decryptPartner(String a_encrypted,SamlProps props) throws CryptoException, Exception
    {
    	
    	javax.xml.parsers.DocumentBuilderFactory dbf =	javax.xml.parsers.DocumentBuilderFactory.newInstance();
    	dbf.setNamespaceAware(true);
    	javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
    	BASE64Decoder decoder = new BASE64Decoder();

    	Document doc = db.parse(new ByteArrayInputStream(decoder.decodeBuffer(a_encrypted)));

    	Element encryptedDataElement =
    		(Element) doc.getElementsByTagNameNS(
    		EncryptionConstants.EncryptionSpecNS,
    		EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);

    	Element e = (Element)
    	doc.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS,
    	EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);
    	XMLCipher cipher = XMLCipher.getInstance();
    	cipher.init(XMLCipher.DECRYPT_MODE, null);

    	EncryptedData encryptedData = cipher.loadEncryptedData(doc, e);

    	if(encryptedData == null)
    	{
    	throw new Exception("EncryptedData is null");
    	}
    	else if (encryptedData.getKeyInfo() == null)
    	{
    	throw new Exception("KeyInfo of the EncryptedData is null");
    	}

    	// get private key from key store
        KeyStore keyStore = CryptoKeystoreUtil.getKeyStore(props
                .getPartnerKeystore(), props.getPartnerKeystorePass().toCharArray());
    	
        KeyPair  keypair  = CryptoKeystoreUtil.getKeyPair(keyStore, props.getPartnerKeystoreAlias(), props.getPartnerKeystorePass().toCharArray());
      //PrivateKey privateKey = (PrivateKey)keyStore.getKey("idp", props.getKeystorePass().toCharArray());
        PrivateKey privateKey = keypair.getPrivate();
    	// get encrypted key data from document
    	EncryptedKey ek = encryptedData.getKeyInfo().itemEncryptedKey(0);
    	Key secretKey = null;
    	if (ek != null)
    	{
    		XMLCipher keyCipher = XMLCipher.getInstance();
    		keyCipher.init(XMLCipher.UNWRAP_MODE, privateKey);
    		secretKey = keyCipher.decryptKey(ek, encryptedData.getEncryptionMethod().getAlgorithm());
    	}
    	XMLCipher xmlCipher = XMLCipher.getInstance();
    	xmlCipher.init(XMLCipher.DECRYPT_MODE, secretKey);

    	xmlCipher.doFinal(doc, encryptedDataElement);

        return convertDocumentToString(doc);
    }*/
    
    /* public String encrypt(String a_text) throws CryptoException, Exception
    {
    	javax.xml.parsers.DocumentBuilderFactory dbf =	javax.xml.parsers.DocumentBuilderFactory.newInstance();
    	dbf.setNamespaceAware(true);
    	javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
    	Document doc = db.parse(new ByteArrayInputStream(a_text.getBytes()));

    	KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    	keyGenerator.init(128);
    	Key symmetricKey = keyGenerator.generateKey();

        KeyStore keystore = CryptoKeystoreUtil.getKeyStore(getSamlProps()
                .getKeystore(), getSamlProps().getKeystorePass().toCharArray());
    	PublicKey publicKey = keystore.getCertificate("idp").getPublicKey();
        
    	String algorithmURI = XMLCipher.RSA_v1dot5;

    	XMLCipher keyCipher =
    	XMLCipher.getInstance(algorithmURI);
    	keyCipher.init(XMLCipher.WRAP_MODE, publicKey);
    	EncryptedKey encryptedKey =
    	keyCipher.encryptKey(doc, symmetricKey);

    	Element rootElement = doc.getDocumentElement();
    	algorithmURI = XMLCipher.AES_128;
    	XMLCipher xmlCipher =
    	XMLCipher.getInstance(algorithmURI);
    	xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);

    	EncryptedData encryptedData = xmlCipher.getEncryptedData();
    	KeyInfo keyInfo = new KeyInfo(doc);
    	keyInfo.add(encryptedKey);
    	encryptedData.setKeyInfo(keyInfo);

    	xmlCipher.doFinal(doc, rootElement, false);

    	BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encodeBuffer(convertDocToString(doc).getBytes());
    }*/
    /* (non-Javadoc)
     * @see com.frequencymarketing.common.app.security.Encryption#encrypt(java.lang.String)
     */
   /* public static String encrypt(String a_text, SamlProps props) throws CryptoException, Exception
    {
    	javax.xml.parsers.DocumentBuilderFactory dbf =	javax.xml.parsers.DocumentBuilderFactory.newInstance();
    	dbf.setNamespaceAware(true);
    	javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
    	Document doc = db.parse(new ByteArrayInputStream(a_text.getBytes()));

    	KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    	keyGenerator.init(128);
    	Key symmetricKey = keyGenerator.generateKey();

        KeyStore keystore = CryptoKeystoreUtil.getKeyStore(props
                .getKeystore(), props.getKeystorePass().toCharArray());
        
        KeyPair  keypair  = CryptoKeystoreUtil.getKeyPair(keystore, props.getKeystoreAlias(), props.getKeystorePass().toCharArray());
        //PublicKey publicKey = keystore.getCertificate("idp").getPublicKey();
        PublicKey publicKey = keypair.getPublic();
    	String algorithmURI = XMLCipher.RSA_v1dot5;

    	XMLCipher keyCipher =
    	XMLCipher.getInstance(algorithmURI);
    	keyCipher.init(XMLCipher.WRAP_MODE, publicKey);
    	EncryptedKey encryptedKey =
    	keyCipher.encryptKey(doc, symmetricKey);

    	Element rootElement = doc.getDocumentElement();
    	algorithmURI = XMLCipher.AES_128;
    	XMLCipher xmlCipher =
    	XMLCipher.getInstance(algorithmURI);
    	xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);

    	EncryptedData encryptedData = xmlCipher.getEncryptedData();
    	KeyInfo keyInfo = new KeyInfo(doc);
    	keyInfo.add(encryptedKey);
    	encryptedData.setKeyInfo(keyInfo);

    	xmlCipher.doFinal(doc, rootElement, false);

    	BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encodeBuffer(convertDocumentToString(doc).getBytes());
    }*/

}
