
package com.bcbs.sso.saml.grcode;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;



/**
 * @author sshaik
 * Common utility class for java keystore.
 */
public class KeystoreUtil
{
	private static Log s_logger = LogFactory.getLog(KeystoreUtil.class);
	
	private static final String lineseparator = System.getProperty ("line.separator");

    public static KeyStore getKeyStore(String p_keystore,
        char[] p_keystorePassword)
    {
        try
        {
        	s_logger.debug(" keystore default type        ---> " + KeyStore.getDefaultType() );
            KeyStore keystore = KeyStore.getInstance(KeyStore
                .getDefaultType());
            keystore.load(KeystoreUtil.class
                .getResourceAsStream(p_keystore), p_keystorePassword);
            
            return keystore;
        }

        catch (Exception e)
        {
        	s_logger.error("Error getting keystore " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }
    
    public static KeyStore getKeyStore (String path, String password)
            throws KeyStoreException
        {
    	
            KeyStore keystore = KeyStore.getInstance (KeyStore.getDefaultType ());
            
            try
            {
                 FileInputStream in = new FileInputStream (path);
                keystore.load (in, password.toCharArray ());
                in.close();
            }catch(IOException ioe)
            {
            	ioe.printStackTrace();
            	s_logger.debug(" Error while loading keystore --> " + ioe.getMessage());
            }catch(NoSuchAlgorithmException nae)
            {
            	nae.printStackTrace();
            	s_logger.debug(" Error while loading keystore --> " + nae.getMessage());
            	
            }catch(CertificateException ce)
            {
            	ce.printStackTrace();
            	s_logger.debug(" Error while loading keystore --> " + ce.getMessage());
            	
            }
           
           
            
            return keystore;
        }
    
    public static KeyStore getKeyStore(String p_keystore, String keyStoreType, char[] p_keystorePassword)
        {

            try
            {
            	s_logger.debug(" keystore default type        ---> " + KeyStore.getDefaultType() );
                KeyStore l_keystore = KeyStore.getInstance(keyStoreType);
                l_keystore.load(KeystoreUtil.class
                    .getResourceAsStream(p_keystore), p_keystorePassword);
                
                return l_keystore;
            }

            catch (Exception e)
            {
            	s_logger.error("Error getting keystore " + e.getMessage());
                e.printStackTrace();
            }
            return null;
        }

    public static Certificate getCertificateFromKeyStore(KeyStore a_keyStore,
        String p_alias)
    {
        try
        {
            Certificate l_cert = a_keyStore.getCertificate(p_alias);

            return l_cert;
        }
        catch (KeyStoreException e)
        {
        	s_logger.error("Error getting certificate from keystore "
                        + e.getMessage());
        }

        return null;

    }

    public static KeyPair getKeyPair(KeyStore p_keystore, String p_alias,
        char[] p_keystorePassword)
    {
        try
        {
            // Get private key
            Key l_key = p_keystore.getKey(p_alias, p_keystorePassword);
            if (l_key instanceof PrivateKey)
            {
                // Get certificate of public key
                java.security.cert.Certificate l_cert = p_keystore
                    .getCertificate(p_alias);

                // Get public key
                PublicKey l_publicKey = l_cert.getPublicKey();

                // Return a key pair
                return new KeyPair(l_publicKey, (PrivateKey)l_key);
            }
        }
        catch (UnrecoverableKeyException e)
        {
        	s_logger.error("Error getting keypair" + e.getMessage());
        }
        catch (NoSuchAlgorithmException e)
        {
        	s_logger.error("Error getting keypair" + e.getMessage());
        }
        catch (KeyStoreException e)
        {
        	s_logger.error("Error getting keypair" + e.getMessage());
        }
        return null;
    }

   /*
    * Return alias  names in keystore. 
    */
    public static List<String> getAliases (KeyStore keystore)
            throws KeyStoreException
        {
            return Collections.list(keystore.aliases ());
        }
    
    /**
    Get a private key from the keystore by name and password.
    */
    public static Key getKey (KeyStore keystore, String alias, String password)
        throws GeneralSecurityException
    {
        return keystore.getKey (alias, password.toCharArray ());
    }
    
    /**
    		Dump key data to log or console.
    */
    public static String getPrivateKeyDump (Key key)
    {
        StringBuffer buffer = new StringBuffer 
            ("Algorithm: " + key.getAlgorithm () + lineseparator +
             "Key value: " + lineseparator);

        appendHexValue (buffer, key.getEncoded ());

        return buffer.toString ();
    }
    
    /**
    	Dump certificate data to log or console.
    */
    public static String getPublicCertDump (java.security.cert.Certificate cert)
        throws GeneralSecurityException
    {
        StringBuffer buffer = new StringBuffer 
            ("Certificate type: " + cert.getType () + lineseparator +
             "Encoded data: " + lineseparator);
        appendHexValue (buffer, cert.getEncoded ());

        return buffer.toString ();
    }
    
    private static void appendHexValue (StringBuffer buffer, byte b)
    {
        int[] digits = { (b >>> 4) & 0x0F, b & 0x0F };
        for (int d = 0; d < digits.length; ++d)
        {
            int increment = (int) ((digits[d] < 10) ? '0' : ('a' - 10));
            buffer.append ((char) (digits[d] + increment));
        }
    }
    
   
    private static void appendHexValue (StringBuffer buffer, byte[] bytes)
    {
        for (int i = 0; i < bytes.length; ++i)
            appendHexValue (buffer, bytes[i]);
    }
    
    public static KeyStore.PrivateKeyEntry getPrivateKeyEntry (KeyStore keyStore, String alias,  String password) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException
    {
    	KeyStore.PrivateKeyEntry privateKeyEntry = null;
    	
    	privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
				alias, new KeyStore.PasswordProtection(
						password.toCharArray()));
    	
    	return privateKeyEntry;
    	
    	
    	
    	
    }
  
}
