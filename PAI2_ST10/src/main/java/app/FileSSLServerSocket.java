package app;

import java.io.*;
import java.security.KeyStore;
import java.sql.*;
import javax.net.ssl.*;

public class FileSSLServerSocket {
    private static final String DB_URL = "jdbc:sqlite:usuarios.db";

    public static void main(String[] args) throws IOException {
        initializeDatabase();

        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("serverkeystore.jks"), "password".toCharArray());

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, "password".toCharArray());

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

            SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(3343);

            System.err.println("Servidor esperando conexiones...");

            while (true) {
                SSLSocket socket = (SSLSocket) serverSocket.accept();
                new ClientHandler(socket).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static class ClientHandler extends Thread {
        private SSLSocket socket;
        private BufferedReader input;
        private PrintWriter output;

        public ClientHandler(SSLSocket socket) throws IOException {
            this.socket = socket;
            this.input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);
        }

        @Override
        public void run() {
            try {
                boolean connected = true;
                while (connected) {
                    String action = input.readLine();
                    if (action == null) {
                        connected = false;
                        break;
                    }

                    String userName = input.readLine();
                    if (userName == null) break;
                    String password = input.readLine();
                    if (password == null) break;

                    if ("register".equals(action)) {
                        output.println(registerUser(userName, password) ? "Registro exitoso." : "Error: El usuario ya existe.");
                    } else if ("login".equals(action)) {
                        if (loginUser(userName, password)) {
                            output.println("Login Successful");
                        } else {
                            output.println("Error: Usuario o contraseña incorrectos.");
                        }
                    } else if (action.startsWith("MENSAJE:")) {
                        incrementMessageCount(userName);
                        output.println("Mensaje registrado correctamente.");
                    } else if ("logout".equals(action)) {
                        output.println("Cerrando sesión...");
                        connected = false;
                    } else {
                        output.println("Error: Acción no válida.");
                    }
                }
            } catch (IOException ioException) {
                ioException.printStackTrace();
            } finally {
                try {
                    input.close();
                    output.close();
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private static void initializeDatabase() {
        try {
            Class.forName("org.sqlite.JDBC");
            Connection conn = DriverManager.getConnection(DB_URL);

            createUsersTable(conn);
            createMessagesDailyTable(conn);

            createTestUserIfNotExist("test1", "test_1", conn);
            createTestUserIfNotExist("test2", "test_2", conn);
            createTestUserIfNotExist("test3", "test_3", conn);

            System.err.println("Base de datos inicializada correctamente.");

        } catch (ClassNotFoundException | SQLException e) {
            e.printStackTrace();
        }
    }

    private static void createUsersTable(Connection conn) {
        try (Statement stmt = conn.createStatement()) {
            String sql = "CREATE TABLE IF NOT EXISTS usuarios (" +
                         "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                         "username TEXT UNIQUE NOT NULL, " +
                         "password TEXT NOT NULL)";
            stmt.execute(sql);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static boolean registerUser(String username, String password) {
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement checkUser = conn.prepareStatement("SELECT COUNT(*) FROM usuarios WHERE LOWER(username) = LOWER(?)")) {
    
            checkUser.setString(1, username);
            ResultSet rs = checkUser.executeQuery();
            
            if (rs.next() && rs.getInt(1) > 0) {
                System.out.println("Intento de registro fallido: el usuario '" + username + "' ya existe.");
                return false; // El usuario ya existe
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement("INSERT INTO usuarios (username, password) VALUES (?, ?)")) {
    
            pstmt.setString(1, username);
            pstmt.setString(2, password);
            pstmt.executeUpdate();
            System.out.println("Usuario '" + username + "' registrado exitosamente.");
            return true;
    
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    

    private static boolean loginUser(String username, String password) {
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement("SELECT password FROM usuarios WHERE username = ?")) {

            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                String storedPassword = rs.getString("password");
                return storedPassword.equals(password);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    private static void createTestUserIfNotExist(String username, String password, Connection conn) {
        try (PreparedStatement pstmt = conn.prepareStatement("SELECT COUNT(*) FROM usuarios WHERE username = ?")) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next() && rs.getInt(1) == 0) {
                createTestUser(username, password, conn);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static void createTestUser(String username, String password, Connection conn) {
        try (PreparedStatement pstmt = conn.prepareStatement("INSERT INTO usuarios (username, password) VALUES (?, ?)")) {
            pstmt.setString(1, username);
            pstmt.setString(2, password);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static void createMessagesDailyTable(Connection conn) {
        try (Statement stmt = conn.createStatement()) {
            String sql = "CREATE TABLE IF NOT EXISTS mensajes_diarios (" +
                         "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                         "username TEXT NOT NULL, " +
                         "fecha DATE NOT NULL, " +
                         "cantidad_mensajes INTEGER DEFAULT 0, " +
                         "UNIQUE(username, fecha))";
            stmt.execute(sql);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static void incrementMessageCount(String username) {
        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            String sqlCheck = "SELECT cantidad_mensajes FROM mensajes_diarios WHERE username = ? AND fecha = DATE('now')";
            try (PreparedStatement pstmtCheck = conn.prepareStatement(sqlCheck)) {
                pstmtCheck.setString(1, username);
                ResultSet rs = pstmtCheck.executeQuery();

                if (rs.next()) {
                    int currentCount = rs.getInt("cantidad_mensajes");
                    String sqlUpdate = "UPDATE mensajes_diarios SET cantidad_mensajes = ? WHERE username = ? AND fecha = DATE('now')";
                    try (PreparedStatement pstmtUpdate = conn.prepareStatement(sqlUpdate)) {
                        pstmtUpdate.setInt(1, currentCount + 1);
                        pstmtUpdate.setString(2, username);
                        pstmtUpdate.executeUpdate();
                    }
                } else {
                    String sqlInsert = "INSERT INTO mensajes_diarios (username, fecha, cantidad_mensajes) VALUES (?, DATE('now'), 1)";
                    try (PreparedStatement pstmtInsert = conn.prepareStatement(sqlInsert)) {
                        pstmtInsert.setString(1, username);
                        pstmtInsert.executeUpdate();
                    }
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
