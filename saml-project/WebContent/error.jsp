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
<form name="samlform" action="<%=java.net.URLDecoder.decode("http://localhost:8080/projectB/index.jsp","UTF-8")%>" method="post">


</form>
</body>
</html>
