<!DOCTYPE html>
<html>

<head>
    <title>Cryptography</title>
    <link rel="stylesheet" type="text/css" href="style.css" media="screen" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
<body> 
        <div class ="nav">
        <A NAME="crypt"></A>
    <ul>
        <li><A HREF="#help">How To Use</A></li>
       <li><a href = "https://www.linkedin.com/in/bryson-marazzi/" >LinkedIn</a></li>
        <li><a href = "https://github.com/brysonmarazzi/CodeLanguage">GitHub</a></li>
    </ul>
        </div>
     <div class="jumbotron">
     <h1>
         <b>B.A.G.S Encryption</b>
    </h1>
    </div>
 <div class="container">
       <div class="Generate">
    <form method="get" action="generate">
        <input type="submit" value="Generate a public and private key combination">
 <%
                     boolean pressed = request.getAttribute("num1")!=null; 
                  if(pressed){
                     %>
         <p>Public Key: <%= request.getAttribute("num1")%></p><p>Private Key: <%= request.getAttribute("num2")%></p>
   <%
     }
     %>
    </form>
       </div>
   
<div class="END">
    
  <form action = "encryptdecrypt" method = "get">    
      
  <u>Encrypt or Decrypt <u id="with">with the corresponding keys:</u><br></u>
       <p>Public Key:
     <textarea id="pub" rows = "1" cols = "52" name = "public"><%if(request.getSession().getAttribute("publicKey") != null){%><%=request.getSession().getAttribute("publicKey")%><%}%></textarea></p>
    <p>Private Key:
     <textarea id="priv" rows = "1" cols = "52" name = "private"><%if(request.getSession().getAttribute("privateKey") != null){%><%=request.getSession().getAttribute("privateKey")%><%}%></textarea></p>
           <textarea id="message" rows = "15" cols = "90" name = "message">Write your message here...</textarea>
      
  <br>Encrypt<input type="radio" name="crypt" value="Encrypt">
  Decrypt<input type="radio" name="crypt" value="Decrypt">
      <input type = "submit" value = "sumbit" /><br>
      
       </form>
    </div>
     
     <div class="OUTPUT">
         <u>Output:<br></u> 
     <textarea rows = "15" cols = "90" name = "message"><%
    if(request.getAttribute("success") != null){
     %><%if((boolean)request.getAttribute("success") == true){%><%=request.getAttribute("output")%>
         <%}else{%><%=request.getAttribute("errorMessage")
          %>
        <%
           }
           }else{%>The output goes here...
           <% }
           %></textarea>
     </div> 
     
     
         <div class="helpSpot">
        <A id="help" NAME="help"></A>
             <u>Summary:</u>
        <p>B.A.G.S Encryption uses a public and private key combination to keep your secret messages safe. This technique is based on the difficult nature of prime factorization for very large numbers. 
        </p>
             <u>
             Steps for Encryption/Decryption with a friend: 
             </u>
   
        <ol>
            <li id = "steps">Generate a public and private key combination. (Do NOT share your private key with anyone and do NOT send your private key over any networks).</li> 
            <li id = "steps">Send your friend the public key so they are able to encrypt their message for you.</li> 
            <li id = "steps">Once your friend has sent you the encrypted message, enter the encrypted message with your public and private key to decrypt.</li>
                      </ol>
                    <p>NOTE: A private key is only needed for decryption, but each private key will only be useful when the message was encrypted with the corresponding public key.</p>
             <li id = "stepsJump"><A HREF="#crypt">Return To Top</A></li>
    </div>
     
     
    </div>

    </body>


</html>
