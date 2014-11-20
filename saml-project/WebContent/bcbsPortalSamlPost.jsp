<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" 
   "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
<title>BCBS Portal - Please wait...</title>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
	<%-- <%@ page import="com.frequencymarketing.citi.view.http.SessionManager" %>
	<%
	SessionManager.setUnusableCache();
	%> --%>
	
  <style>
        html{display : none ; } 
  </style>

  <script type="text/javascript">
	if( self == top ) 
     { document.documentElement.style.display = 'block' ; } 
     else 
     { top.location = self.location ; }
  </script>
		
<script language="JavaScript">
function goToPartner()
{
	document.samlform.submit();
}
</script>
</head>
<body onLoad="javascript:goToPartner()">
<p>&nbsp;</p>
<%-- <form name="samlform" action="<%=java.net.URLDecoder.decode((String)request.getAttribute("SAMLURL"),"UTF-8")%>" method="post"> --%>
<form name="samlform" action="<%=request.getContextPath()%>/portalLoginTestSaml.jspx" method="post">
<input type="hidden" name="SAMLResponse" id="SAMLResponse" value="<%=request.getAttribute("SAMLResponse")%>">
<logic:present name="TARGET" scope="request">
<input type="hidden" name="TARGET" id="TARGET" value="<%=request.getAttribute("TARGET")%>">
</logic:present>
</form>
</body>
</html>