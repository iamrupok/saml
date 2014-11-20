package com.bcbs.sso.view.http.struts.action.external;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.log4j.Logger;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import com.bcbs.sso.common.saml.model.BcbsSamlProfileData;
import com.bcbs.sso.saml.BcbsLoginProps;
import com.bcbs.sso.saml.grcode.InitializeSAMLData;
import com.bcbs.sso.view.http.struts.form.LoginForm;
 
public class PortalSaml2LoginSubmitAction extends Action {
	
	public static final String BCBS_PARTNER_ID = "BCBS";
	 //private static Log s_logger = LogFactory.getLog(BcbsPortalSaml2LoginAction.class);
	 static Logger s_logger = Logger.getLogger(BcbsPortalSaml2LoginAction.class);
	
	ApplicationContext applicationContext = null;
	
 
    public ActionForward execute(ActionMapping mapping, ActionForm form,
            HttpServletRequest request, HttpServletResponse response)
            throws Exception {
    	
    	
     
        String target = null;
        LoginForm loginForm = (com.bcbs.sso.view.http.struts.form.LoginForm)form;
        
        BcbsSamlProfileData  memberData= new BcbsSamlProfileData();
        String secretKey="4909efbfbdefbfbdefbfbdefbfbd5fefbfbdefbfbd417100efbfbdefbfbd6cefbfbd4aefbfbdefbfbd2cefbfbdefbfbd1768e8869860efbfbd10efbfbdefbfbd1fefbfbd077508efbfbdefbfbdefbfbd6defbfbd6e7ceb859befbfbdefbfbd23efbfbd1157efbfbd2b06efbfbd5b7defbfbd";
        memberData.setSecretKey(secretKey);
        memberData.setUserId(loginForm.getUserName());
        
        setBcbsSaml(memberData,BCBS_PARTNER_ID,request);
             
        if(loginForm.getUserName().equals("admin")
                && loginForm.getPassword().equals("admin123")) {
            target = "success";
            request.setAttribute("message", loginForm.getPassword());
        }
        else {
            target = "failure";
        }
        
    	s_logger.debug(" Forwarding action ------------> " + target);
         
        return mapping.findForward(target);
    }
    
    protected void setBcbsSaml(BcbsSamlProfileData memberData,  String partnerId, HttpServletRequest request)throws Exception
    {
    	
    	applicationContext = WebApplicationContextUtils.getWebApplicationContext(request.getSession().getServletContext());
    	BcbsLoginProps props = (BcbsLoginProps)applicationContext.getBean("bcbsLoginProps");
        InitializeSAMLData initializeSAMLData = new InitializeSAMLData();
        initializeSAMLData.initializeSAMLData(partnerId, props,memberData, request);
       
    }
}