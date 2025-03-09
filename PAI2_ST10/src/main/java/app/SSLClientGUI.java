package app;

import javax.net.ssl.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.security.KeyStore;

public class SSLClientGUI {
    private JFrame frame;
    private JTextField usernameField, messageField;
    private JPasswordField passwordField;
    private JTextArea responseArea;
    private SSLSocket socket;
    private PrintWriter output;
    private BufferedReader input;
    private boolean sessionActive = false;

    public SSLClientGUI() {
        initializeSSL();
        initializeGUI();
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
            JOptionPane.showMessageDialog(null, "Error initializing SSL connection: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(1);
        }
    }

    private void initializeGUI() {
        frame = new JFrame("SSL Client");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 300);
        frame.setLayout(new BorderLayout());

        JPanel panel = new JPanel(new GridLayout(5, 1));
        usernameField = new JTextField("Usuario");
        passwordField = new JPasswordField("Contraseña");
        JButton loginButton = new JButton("Iniciar Sesión");
        JButton registerButton = new JButton("Registrar");
        JButton sendMessageButton = new JButton("Enviar Mensaje");
        messageField = new JTextField("Escribe tu mensaje");
        responseArea = new JTextArea(5, 20);
        responseArea.setEditable(false);

        panel.add(usernameField);
        panel.add(passwordField);
        panel.add(loginButton);
        panel.add(registerButton);
        panel.add(messageField);
        panel.add(sendMessageButton);
        frame.add(panel, BorderLayout.CENTER);
        frame.add(new JScrollPane(responseArea), BorderLayout.SOUTH);

        loginButton.addActionListener(e -> sendRequest("login"));
        registerButton.addActionListener(e -> sendRequest("register"));
        sendMessageButton.addActionListener(e -> sendMessage());

        frame.setVisible(true);
    }

    private void sendRequest(String action) {
        try {
            String userName = usernameField.getText().trim();
            String password = new String(passwordField.getPassword()).trim();

            if (userName.isEmpty() || password.isEmpty()) {
                responseArea.append("Ingrese usuario y contraseña.\n");
                return;
            }

            output.println(action);
            output.println(userName);
            output.println(password);
            output.flush();

            String response = input.readLine();
            responseArea.append(response + "\n");

            JOptionPane.showMessageDialog(frame, response, "Respuesta del servidor", JOptionPane.INFORMATION_MESSAGE);
            if ("Login Successful".equals(response)) {
                sessionActive = true;
            }
        } catch (IOException e) {
            responseArea.append("Error al comunicarse con el servidor.\n");
            JOptionPane.showMessageDialog(frame, "Error al comunicarse con el servidor.", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void sendMessage() {
        if (!sessionActive) {
            JOptionPane.showMessageDialog(frame, "Debe iniciar sesión antes de enviar un mensaje.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        String message = messageField.getText();
        output.println("MENSAJE: " + message);
        responseArea.append("Mensaje enviado: " + message + "\n");
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(SSLClientGUI::new);
    }
}
