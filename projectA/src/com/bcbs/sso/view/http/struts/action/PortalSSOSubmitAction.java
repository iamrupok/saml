package com.bcbs.sso.view.http.struts.action;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;

public class PortalSSOSubmitAction extends Action{

	 static Logger s_logger = Logger.getLogger(PortalSSOSubmitAction.class);
	 public ActionForward execute(ActionMapping mapping, ActionForm form,
	            HttpServletRequest request, HttpServletResponse response)
	            throws Exception {
	    	
	    	String target = "failure";
	        		
			String saml=(String)request.getSession().getAttribute("SAMLResponse");
	             
	        if(saml!=null) {
	            target = "success";
	            
	        }
	        
	       s_logger.debug(" Forwarding action ------------> " + target);
	       return mapping.findForward(target);
	    }
}
