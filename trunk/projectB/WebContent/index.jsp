<%@taglib uri="http://jakarta.apache.org/struts/tags-html" prefix="html"%>
<%@taglib uri="http://jakarta.apache.org/struts/tags-bean" prefix="bean" %>
 
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
        <title>Login page | Hello World Struts application in Eclipse</title>
    </head>
    <body>
    <h1>Portal Login</h1>
    <h3>User ID:  <%=(String)request.getSession().getAttribute("MyUser")%>   ,   Shared Key:  <%=(String)request.getSession().getAttribute("MySecret")%></h3>
    </body>
</html>