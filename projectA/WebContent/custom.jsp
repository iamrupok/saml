<html>
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
</html> --%>