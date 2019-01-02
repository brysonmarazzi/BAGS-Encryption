import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class encryptdecryptServlet  extends HttpServlet {

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        String errorMessage = "";
        String publicAndExpo = request.getParameter("public");
        String privateKey = request.getParameter("private");
        String message = request.getParameter("message");
        //find out if it is encryption or decryption
        String radio = request.getParameter("crypt");
        boolean encrypt = "Encrypt".equals(radio);
        boolean decrypt = "Decrypt".equals(radio);
        //check for bad input.
        if("Encrypt".equals(radio) || "Decrypt".equals(radio)) {
            if ("Encrypt".equals(radio) && !isValidEncrypt(publicAndExpo, message).equals(""))
                errorMessage = "Error: " + isValidEncrypt(publicAndExpo, message);
            if ("Decrypt".equals(radio) && !isValidDecrypt(publicAndExpo, privateKey, message).equals(""))
                errorMessage = "Error: " + isValidDecrypt(publicAndExpo, privateKey, message);
        }else errorMessage = "Error: You need to select an option.";

        HttpSession session = request.getSession();
        session.setAttribute("publicKey",publicAndExpo);
        session.setAttribute("privateKey",privateKey);

        boolean success = (errorMessage.equals(""));

        request.setAttribute("success",success);

        if(!success){
            request.setAttribute("errorMessage",errorMessage);
        }else{
//        check the last digit to see how many digits the exponent is.
            int digitsOfExponent = Integer.parseInt(publicAndExpo.substring(publicAndExpo.length()-1,publicAndExpo.length()));
            String exponent = publicAndExpo.substring(publicAndExpo.length()-1-digitsOfExponent,publicAndExpo.length()-1);
            String publicKey = publicAndExpo.substring(0,publicAndExpo.length()-1-digitsOfExponent);

            if(encrypt) {
                try {
                    String cipherMessage = Encryption.encrypt(message, exponent, publicKey);
                    request.setAttribute("output", cipherMessage);
                }catch(Exception e){
                    request.setAttribute("success",false);
                    errorMessage = "There is something wrong with your input.";
                    request.setAttribute("errorMessage",errorMessage);
                    request.getRequestDispatcher("cryptographyGenerate.jsp").forward(request, response);
                }
            }

            if(decrypt){
                try {
                String plainText = Encryption.decrypt(message,privateKey,publicKey);
                request.setAttribute("output", plainText);
            }catch(Exception e){
                request.setAttribute("success",false);
                errorMessage = "There is something wrong with your input.";
                request.setAttribute("errorMessage",errorMessage);
                request.getRequestDispatcher("cryptographyGenerate.jsp").forward(request, response);
            }
            }
        }
//        Public Key: 92998929342693278971
//
//        Private Key: 265711226142346783


        //send the control to the jsp
        request.getRequestDispatcher("cryptographyGenerate.jsp").forward(request, response);

    }

    private static String isValidEncrypt(String publicKey, String message){
        if(publicKey == null || message == null){
            return "You are missing some vital information.";
        }
        if(publicKey.length() < 2) return "The publicKey is invalid.";
        for(Character c : publicKey.toCharArray()){
            if(!Character.isDigit(c)) return "The publicKey can only consist of digits!";
        }
        return "";
    }

    private static String isValidDecrypt(String publicKey, String privateKey, String message){
        if(publicKey == null || privateKey == null || message == null) return "You are missing some vital information.";
        if(publicKey.length() < 2)  return "The publicKey is invalid.";
        for(Character c : publicKey.toCharArray()){
            if(!Character.isDigit(c)) return "The publicKey can only consist of digits!";
        }
        for(Character c : privateKey.toCharArray()){
            if(!Character.isDigit(c)) return "The privateKey can only consist of digits!";
        }
        return "";
    }


}