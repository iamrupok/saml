package com.bcbs.sso.common.saml.app.security;


public class CryptoException extends Exception
{
    /**
     * Construct
     * @param a_message
     */
    public CryptoException(String a_message)
    {
        super(a_message);
    }
    
    /**
     * Contruct
     * @param a_message
     * @param a_exception
     */
    public CryptoException(String a_message, Exception a_exception)
    {
        super(a_message, a_exception);
    }
}
