import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class generateServlet extends HttpServlet {

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        String[] keys = Encryption.generateKeys();
        request.setAttribute("num2",keys[0]);
        request.setAttribute("num1",keys[1]);
        request.getRequestDispatcher("cryptographyGenerate.jsp").forward(request, response);
    }
}