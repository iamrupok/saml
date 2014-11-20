package com.bcbs.sso.view.http.struts.action;

import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import com.bcbs.sso.common.saml.model.SamlProfileData;
import com.bcbs.sso.saml.BcbsLoginProps;
import com.bcbs.sso.saml.grcode.InitializeSAMLData;
import com.bcbs.sso.view.http.struts.form.LoginForm;
 
public class PortalLoginSubmitAction extends Action {
	
	public static final String BCBS_PARTNER_ID = "BCBS";
	
	 static Logger s_logger = Logger.getLogger(PortalLoginSubmitAction.class);
	
	ApplicationContext applicationContext = null;
	private static String algorithm = "AES";
	private static byte[] keyValue=new byte[] {'0','2','3','4','5','6','7','8','9','1','2','3','4','5','6','7'};// your key

 
    public ActionForward execute(ActionMapping mapping, ActionForm form,
            HttpServletRequest request, HttpServletResponse response)
            throws Exception {
    	
    	
     
        String target = null;
        LoginForm loginForm = (com.bcbs.sso.view.http.struts.form.LoginForm)form;
        
        SamlProfileData  memberData= new SamlProfileData();
        memberData.setSecretKey(encrypt(loginForm.getPassword(),loginForm.getPassword()));
        memberData.setUserId(loginForm.getUserName());
        setBcbsSaml(memberData,BCBS_PARTNER_ID,request);
             
        if(loginForm.getUserName()!=null && loginForm.getPassword()!=null) {
            target = "success";
            request.getSession().setAttribute("message", loginForm.getUserName());
        }
        else {
            target = "failure";
        }
       s_logger.debug(" Forwarding action ------------> " + target);
       return mapping.findForward(target);
    }
    
    protected void setBcbsSaml(SamlProfileData memberData,  String partnerId, HttpServletRequest request)throws Exception
    {
    	
    	applicationContext = WebApplicationContextUtils.getWebApplicationContext(request.getSession().getServletContext());
    	BcbsLoginProps props = (BcbsLoginProps)applicationContext.getBean("bcbsLoginProps");
        InitializeSAMLData initializeSAMLData = new InitializeSAMLData();
        initializeSAMLData.initializeSAMLData(partnerId, props,memberData, request);
       
    }
    
    public String secretKey(String userName,String passWord){
    	String SALT2 = "deliciously salty";
    	MessageDigest sha;
    	SecretKeySpec secretKeySpec=null;
		try {
			byte[] key = (SALT2 + userName + passWord).getBytes("UTF-8");
			sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
	    	key = Arrays.copyOf(key, 16); // use only first 128 bit
	    	secretKeySpec = new SecretKeySpec(key, "AES");
		} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	
		return secretKeySpec.toString();
    	 
    }
    public static String encrypt(String userName,String passWord) throws Exception 
    {
    	 	String plainText=userName+userName;
            Key key = generateKey();
            Cipher chiper = Cipher.getInstance(algorithm);
            chiper.init(Cipher.ENCRYPT_MODE, key);
            byte[] encVal = chiper.doFinal(plainText.getBytes());
            String encryptedValue = new BASE64Encoder().encode(encVal);
            return encryptedValue;
    }

    // Performs decryption
    public  String decrypt(String userName,String passWord) throws Exception 
    {
            // generate key 
            String encryptedText=userName+userName;
    		Key key = generateKey();
            Cipher chiper = Cipher.getInstance(algorithm);
            chiper.init(Cipher.DECRYPT_MODE, key);
            byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedText);
            byte[] decValue = chiper.doFinal(decordedValue);
            String decryptedValue = new String(decValue);
            return decryptedValue;
    }
    private static Key generateKey() throws Exception 
    {
            Key key = new SecretKeySpec(keyValue, algorithm);
            return key;
    }
}