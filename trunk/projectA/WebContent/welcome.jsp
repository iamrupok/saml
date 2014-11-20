<%-- <%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
        <title>Welcome page | Hello World Struts application in Eclipse</title>
    </head>
    <body>
    <%
        String message = (String)request.getSession().getAttribute("message");
        String contextPath = request.getContextPath();
    %>
        
        <h1>Welcome <%= message %> at </h1>
        
         <p>Log In to   </p><a href="<%= contextPath %>/loginSeamless2.jspx"> (SAML-2.0)</a>
         <p>
         	<%=(String)request.getSession().getAttribute("SAMLResponse")%>
         </p>
        	
     	 <p>
         	<%=(String)request.getSession().getAttribute("SAMLURL")%>
         </p>
        
    </body>
</html>

<html> --%>
 <head>
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
<form name="samlform" action="<%=java.net.URLDecoder.decode("http://localhost:8080/saml-project/portalLoginSaml.jspx","UTF-8")%>" method="post">
<input type="hidden" name="SAMLResponse" id="SAMLResponse" value="<%=(String)request.getSession().getAttribute("SAMLResponse")%>">
</form>
</body>
</html>