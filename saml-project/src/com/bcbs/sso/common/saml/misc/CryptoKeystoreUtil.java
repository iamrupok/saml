/*
     * @(#) CryptoKeystoreUtil.java Feb 6, 2006
     * Copyright 2005 Frequency Marketing, Inc. All rights reserved.
     * Frequency Marketing, Inc. PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
     */
package com.bcbs.sso.common.saml.misc;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import org.apache.log4j.Logger;

/**
 * @author Saleem Jeelani Dec 20, 2005
 */
public class CryptoKeystoreUtil
{
    //	private static final Log s_log = LogFactory.getLog("CryptoKeystoreUtil");
    private static final Logger s_log = Logger.getLogger("CryptoKeystoreUtil");

    public static KeyStore getKeyStore(String p_keystore,
        char[] p_keystorePassword)
    {

        try
        {
            KeyStore l_keystore = KeyStore.getInstance(KeyStore
                .getDefaultType());
            l_keystore.load(CryptoKeystoreUtil.class
                .getResourceAsStream(p_keystore), p_keystorePassword);
            return l_keystore;
        }

        catch (Exception e)
        {
            s_log.error("Error getting keystore " + e.getMessage());
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
            s_log.error("Error getting certificate from keystore "
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
            s_log.error("Error getting keypair" + e.getMessage());
        }
        catch (NoSuchAlgorithmException e)
        {
            s_log.error("Error getting keypair" + e.getMessage());
        }
        catch (KeyStoreException e)
        {
            s_log.error("Error getting keypair" + e.getMessage());
        }
        return null;
    }

}
