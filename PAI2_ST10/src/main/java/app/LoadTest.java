package app;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
public class LoadTest {

    public static void main(String[] args) {
        // Crear un pool de hilos para manejar múltiples clientes
        ExecutorService executorService = Executors.newFixedThreadPool(10); // Pool con 10 hilos

        // Registrar 300 usuarios
        for (int i = 1; i <= 300; i++) {
            final int userId = i;
            executorService.submit(() -> {
                try {
                    SSLClient client = new SSLClient("user" + userId, "password" + userId);
                    // client.register();  // Registro del usuario, por defecto deshabilitado, descomentar si se reinicia la base de datos
                    client.login();     // Inicio de sesión del usuario
                    if (client.sendMessage("Mensaje de prueba de usuario " + userId)) {
                        System.out.println("Mensaje enviado correctamente por el usuario " + userId);
                    }
                } catch (IOException e) {
                    System.err.println("Error para el usuario " + userId + ": " + e.getMessage());
                }
            });
        }

        // Detener el pool de hilos después de completar todos los trabajos
        executorService.shutdown();

        // Esperar a que todos los hilos terminen y luego mostrar el contador
        while (!executorService.isTerminated()) {
            // Esperar hasta que todos los clientes hayan terminado
        }

    }
}

class SSLClient {
    private String username;
    private String password;
    private SSLSocket socket;
    private PrintWriter output;
    private BufferedReader input;

    public SSLClient(String username, String password) {
        this.username = username;
        this.password = password;
        initializeSSL();
    }

    private void initializeSSL() {
        try {
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream("clienttruststore.jks"), "password".toCharArray());

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

            SSLSocketFactory factory = sslContext.getSocketFactory();
            socket = (SSLSocket) factory.createSocket("localhost", 3343);

            socket.setEnabledProtocols(new String[]{"TLSv1.3"});
            socket.setEnabledCipherSuites(new String[]{
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256"
            });

            output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);
            input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        } catch (Exception e) {
            System.err.println("Error al inicializar la conexión SSL: " + e.getMessage());
        }
    }

    // Método para registrar al usuario
    public void register() throws IOException {
        output.println("register");
        output.println(username);
        output.println(password);
        output.flush();

        String response = input.readLine();
        System.out.println("Respuesta del servidor para registro de " + username + ": " + response);
    }

    public void login() throws IOException {
        output.println("login");
        output.println(username);
        output.println(password);
        output.flush();

        String response = input.readLine();
        System.out.println("Respuesta del servidor para " + username + ": " + response);
    }

    public synchronized boolean sendMessage(String message) throws IOException {
        output.println("sendMessage");
        output.println(username);
        output.println(message);
        output.flush();

        String response = input.readLine();
        System.out.println("Respuesta del servidor: " + response); // Depuración
        if (response != null && response.contains("Mensaje recibido")) {
            System.out.println("Mensaje enviado correctamente por " + username);
            return true; // Mensaje enviado con éxito
        } else {
            System.err.println("Error al enviar el mensaje de " + username);
            return false; // Error al enviar el mensaje
        }
    }
}
