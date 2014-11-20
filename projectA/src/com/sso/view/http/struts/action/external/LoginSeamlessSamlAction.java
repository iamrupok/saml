package com.sso.view.http.struts.action.external;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.w3c.dom.Element;

import com.bcbs.sso.common.saml.model.SamlProfileData;
import com.bcbs.sso.saml.BcbsLoginProps;
import com.bcbs.sso.saml.grcode.InitializeSAMLData;




public class LoginSeamlessSamlAction extends Action {

	public static String ACTION_NAME = "sso";
	private static Log s_logger = LogFactory
			.getLog(LoginSeamlessSamlAction.class);

	
	ApplicationContext applicationContext = null;

	public static final String FORWARD_FAILURE = "failure";
	public static final String FORWARD_SUCCESS = "success";

	public ActionForward execute(ActionMapping mapping, ActionForm form,
			HttpServletRequest request, HttpServletResponse response)
			throws Exception {
		String forward = FORWARD_FAILURE;


		return null;
	}
	
	
}
