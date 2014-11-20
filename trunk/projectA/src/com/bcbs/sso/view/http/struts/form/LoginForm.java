package com.bcbs.sso.view.http.struts.form;

import javax.servlet.http.HttpServletRequest;
import org.apache.struts.action.ActionErrors;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionMapping;
import org.apache.struts.action.ActionMessage;

public class LoginForm extends ActionForm {

	 private String userName;
	    private String password;
	     
	    public ActionErrors validate(ActionMapping mapping,
	            HttpServletRequest request) {
	     
	        ActionErrors actionErrors = new ActionErrors();
	         
	        if(userName == null || userName.trim().equals("")) {
	            actionErrors.add("userName", new ActionMessage("error.username"));
	        }
	        try {
	        if(password == null || password.trim().equals("")) {
	            actionErrors.add("password", new ActionMessage("error.password"));
	        }
	        }catch(Exception e) {
	            e.printStackTrace();
	        }
	        return actionErrors ;
	    }
	     
	    public String getUserName() {
	        return userName;
	    }
	    public void setUserName(String userName) {
	        this.userName = userName;
	    }
	    public String getPassword() {
	        return password;
	    }
	    public void setPassword(String password) {
	        this.password = password;
	    }
}
