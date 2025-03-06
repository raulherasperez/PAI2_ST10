package app;

import javax.net.ssl.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
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
    private JTabbedPane tabbedPane;
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

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

            SSLSocketFactory factory = sslContext.getSocketFactory();
            socket = (SSLSocket) factory.createSocket("localhost", 3343);
            socket.setEnabledProtocols(new String[]{"TLSv1.2"});
            socket.setEnabledCipherSuites(new String[]{
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            });

            output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);
            input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, "Error initializing SSL connection", "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(1);
        }
    }

    private void initializeGUI() {
        frame = new JFrame("SSL Client");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 300);
        frame.setLayout(new BorderLayout());

        tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Login", createAuthPanel());
        tabbedPane.addTab("Mensajería", createMessagePanel());
        tabbedPane.setEnabledAt(1, false);

        frame.add(tabbedPane, BorderLayout.CENTER);
        frame.setVisible(true);
    }

    private JPanel createAuthPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridx = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        usernameField = createStyledTextField("Usuario");
        passwordField = createStyledPasswordField("Contraseña");
        JButton loginButton = createStyledButton("Iniciar Sesión", new Color(46, 204, 113));
        JButton registerButton = createStyledButton("Registrar", new Color(52, 152, 219));

        loginButton.addActionListener(e -> sendRequest("login"));
        registerButton.addActionListener(e -> sendRequest("register"));

        gbc.gridy = 0; panel.add(usernameField, gbc);
        gbc.gridy = 1; panel.add(passwordField, gbc);
        gbc.gridy = 2; panel.add(loginButton, gbc);
        gbc.gridy = 3; panel.add(registerButton, gbc);

        return panel;
    }

    private JPanel createMessagePanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridx = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        messageField = createStyledTextField("Escribe tu mensaje");
        JButton sendMessageButton = createStyledButton("Enviar", new Color(231, 76, 60));
        JButton logoutButton = createStyledButton("Cerrar Sesión", new Color(192, 57, 43));

        sendMessageButton.addActionListener(e -> sendMessage());
        logoutButton.addActionListener(e -> logout());

        gbc.gridy = 0; panel.add(messageField, gbc);
        gbc.gridy = 1; panel.add(sendMessageButton, gbc);
        gbc.gridy = 2; panel.add(logoutButton, gbc);

        responseArea = new JTextArea(5, 20);
        responseArea.setEditable(false);
        gbc.gridy = 3; panel.add(new JScrollPane(responseArea), gbc);

        return panel;
    }

    private JTextField createStyledTextField(String placeholder) {
        JTextField field = new JTextField(15);
        field.setPreferredSize(new Dimension(200, 30));
        setPlaceholder(field, placeholder);
        return field;
    }

    private JPasswordField createStyledPasswordField(String placeholder) {
        JPasswordField field = new JPasswordField(15);
        field.setPreferredSize(new Dimension(200, 30));
        setPlaceholder(field, placeholder);
        return field;
    }

    private JButton createStyledButton(String text, Color color) {
        JButton button = new JButton(text);
        button.setBackground(color);
        button.setForeground(Color.WHITE);
        button.setPreferredSize(new Dimension(200, 40));
        return button;
    }

    private void setPlaceholder(JTextField field, String placeholder) {
        field.setText(placeholder);
        field.setForeground(Color.GRAY);
        field.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {
                if (field.getText().equals(placeholder)) {
                    field.setText("");
                    field.setForeground(Color.BLACK);
                }
            }
            @Override
            public void focusLost(FocusEvent e) {
                if (field.getText().isEmpty()) {
                    field.setText(placeholder);
                    field.setForeground(Color.GRAY);
                }
            }
        });
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
    
            // Mostrar respuesta en una ventana emergente
            JOptionPane.showMessageDialog(frame, response, "Respuesta del servidor", JOptionPane.INFORMATION_MESSAGE);
    
            if (response.equals("Login Successful")) {
                sessionActive = true;
                tabbedPane.setEnabledAt(1, true);
                tabbedPane.setSelectedIndex(1);
            }
        } catch (IOException e) {
            responseArea.append("Error al comunicarse con el servidor.\n");
            JOptionPane.showMessageDialog(frame, "Error al comunicarse con el servidor.", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    private void sendMessage() {
        String message = messageField.getText();
        output.println("MENSAJE: " + message);
        responseArea.append("Mensaje: " + message + "\n");
    
        // Mostrar confirmación en una ventana emergente
        JOptionPane.showMessageDialog(frame, "Mensaje enviado: " + message, "Mensaje Enviado", JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void logout() {
        sessionActive = false;
        tabbedPane.setEnabledAt(1, false);
        tabbedPane.setSelectedIndex(0);
    
        // Mostrar mensaje de cierre de sesión en una ventana emergente
        JOptionPane.showMessageDialog(frame, "Has cerrado sesión", "Sesión cerrada", JOptionPane.INFORMATION_MESSAGE);
    }


    public static void main(String[] args) {
        SwingUtilities.invokeLater(SSLClientGUI::new);
    }
}