
package app;
import java.io.*;
import java.security.KeyStore;
import javax.net.ssl.*;
import javax.swing.JOptionPane;

public class SSLClientSocket {

    public static void main(String[] args) throws IOException {
        try {
            // Load the TrustStore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream("clienttruststore.jks"), "password".toCharArray());

            // Initialize the TrustManagerFactory
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Initialize the SSLContext
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

            SSLSocketFactory factory = sslContext.getSocketFactory();
            SSLSocket socket = (SSLSocket) factory.createSocket("localhost", 3343);

            // Specify the protocols and cipher suites
            socket.setEnabledProtocols(new String[] {"TLSv1.2"});
            socket.setEnabledCipherSuites(new String[] {
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            });

            PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);
            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            String[] options = {"Register", "Login"};
            int choice = JOptionPane.showOptionDialog(null, "Do you want to register or login?",
                    "Select Option", JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, options, options[0]);

            String userName = JOptionPane.showInputDialog(null, "Enter User Name:");
            String password = JOptionPane.showInputDialog(null, "Enter Password:");
            String action = (choice == 0) ? "register" : "login";

            output.println(action);
            output.println(userName);
            output.println(password);
            output.flush();

            String response = input.readLine();
            JOptionPane.showMessageDialog(null, response);

            // display response to user
            JOptionPane.showMessageDialog(null, response);

            // clean up streams and Socket
            output.close();
            input.close();
            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            System.exit(0);
        }
    }
}