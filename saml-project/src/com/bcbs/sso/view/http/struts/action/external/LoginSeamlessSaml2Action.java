package com.bcbs.sso.view.http.struts.action.external;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import com.bcbs.sso.common.saml.model.BcbsSamlProfileData;
import com.bcbs.sso.saml.BcbsPortalSaml;
import com.bcbs.sso.saml.StringUtils;

public class LoginSeamlessSaml2Action extends Action {
 
	static Logger s_logger = Logger.getLogger(LoginSeamlessSaml2Action.class);

    private String forward;
    public static final String FORWARD_FAILURE = "failure";
    public static final String FORWARD_SUCCESS = "success";
    
    ApplicationContext applicationContext = null;
    
    public ActionForward execute(ActionMapping mapping, ActionForm form,
            HttpServletRequest request, HttpServletResponse response)
            throws Exception {
    	
   
        
        forward = FORWARD_FAILURE;
		

		try {
			
			 
			
			String loginSAML2Response = request.getParameter("SAMLResponse");
			if (!StringUtils.isEmpty(loginSAML2Response)) {
				applicationContext = WebApplicationContextUtils.getWebApplicationContext(request.getSession().getServletContext());
				BcbsPortalSaml bcbsPortalSaml = (BcbsPortalSaml)applicationContext.getBean("bcbsPortalSaml");
				BcbsSamlProfileData bcbsSamlProfileData = bcbsPortalSaml.processLoginResponseSAML2(loginSAML2Response);				
				s_logger.debug("\n\n BCBS Profile Data: " + bcbsSamlProfileData.toString());
				

			}

			forward  = FORWARD_SUCCESS;	
			
		} catch (Exception e) {
			e.printStackTrace();
			s_logger.error("Error in processing SAML Response", e);
		}
        
		s_logger.debug(" Forwarding action ------------> " + forward);

		 return mapping.findForward(forward);
		 
		 
    }
}