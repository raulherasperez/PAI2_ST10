package app;

import java.io.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.*;
import javax.net.ssl.*;
import utils.SaltManager;

public class FileSSLServerSocket {
    private static final String DB_URL = "jdbc:sqlite:usuarios.db";

    public static void main(String[] args) throws IOException, InterruptedException {
        initializeDatabase();

        try {
            // Load the KeyStore
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("serverkeystore.jks"), "password".toCharArray());

            // Initialize the KeyManagerFactory
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, "password".toCharArray());

            // Initialize the SSLContext
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

            SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(3343);

            System.err.println("Waiting for connection...");

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
                    String password = input.readLine();

                    if ("register".equals(action)) {
                        output.println(registerUser(userName, password) ? "Registro exitoso." : "Error: El usuario ya existe.");
                    } else if ("login".equals(action)) {
                        if (loginUser(userName, password)) {
                            output.println("Login Successful");
                        } else {
                            output.println("Error: Usuario o contraseña incorrectos.");
                        }
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
            Class.forName("org.sqlite.JDBC"); // Cargar manualmente el driver
            Connection conn = DriverManager.getConnection(DB_URL);

            File dbFile = new File("usuarios.db");
            boolean databaseExists = dbFile.exists();

            if (!databaseExists) {
                System.err.println("La base de datos no existe. Creando base de datos y usuarios de prueba...");

                // Crear la tabla de usuarios si no existe
                createUsersTable(conn);

                // Verificar si los usuarios de prueba existen, y si no, crearlos
                createTestUserIfNotExist("test1", "test_1", conn);
                createTestUserIfNotExist("test2", "test_2", conn);
                createTestUserIfNotExist("test3", "test_3", conn);

                System.err.println("Base de datos y usuarios de prueba creados exitosamente.");
            } else {
                System.err.println("La base de datos ya existe.");

                // Si la base de datos ya existe, verificamos si los usuarios de prueba existen y los creamos si no
                createUsersTable(conn); // Crear la tabla si no existe
                createTestUserIfNotExist("test1", "test_1", conn);
                createTestUserIfNotExist("test2", "test_2", conn);
                createTestUserIfNotExist("test3", "test_3", conn);
            }
        } catch (ClassNotFoundException | SQLException e) {
            e.printStackTrace();
        }
    }

    private static void createUsersTable(Connection conn) {
        try (Statement stmt = conn.createStatement()) {
            String sql = "CREATE TABLE IF NOT EXISTS usuarios (" +
                         "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                         "username TEXT UNIQUE NOT NULL, " +
                         "password TEXT NOT NULL, " +
                         "salt TEXT NOT NULL)";
            stmt.execute(sql);
        } catch (SQLException e) {
            e.printStackTrace();
        }
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
        String salt = generateSalt();
        String hashedPassword = hashPassword(password, salt);

        try (PreparedStatement pstmt = conn.prepareStatement("INSERT INTO usuarios (username, password, salt) VALUES (?, ?, ?)")) {
            pstmt.setString(1, username);
            pstmt.setString(2, hashedPassword);
            SaltManager.saveSalt(username, salt); // Guarda la salt cifrada
            pstmt.setString(3, "encrypted"); // Indica que la salt está almacenada cifrada externamente
            pstmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static boolean registerUser(String username, String password) {
        // Verificar si el usuario ya existe
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement checkUser = conn.prepareStatement("SELECT COUNT(*) FROM usuarios WHERE username = ?")) {
    
            checkUser.setString(1, username);
            ResultSet rs = checkUser.executeQuery();
            if (rs.next() && rs.getInt(1) > 0) {
                System.out.println("El usuario ya existe.");
                // El usuario ya existe
                return false;
                
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    
        // Si el usuario no existe, proceder con el registro
        String salt = generateSalt();
        String hashedPassword = hashPassword(password, salt);
    
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement("INSERT INTO usuarios (username, password, salt) VALUES (?, ?, ?)")) {
    
            pstmt.setString(1, username);
            pstmt.setString(2, hashedPassword);
            SaltManager.saveSalt(username, salt); // Guarda la salt cifrada
            pstmt.setString(3, "encrypted"); // Indica que la salt está almacenada cifrada externamente
            pstmt.executeUpdate();
            return true;
    
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    

    private static boolean loginUser(String username, String password) {
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement("SELECT password, salt FROM usuarios WHERE username = ?")) {

            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                String storedPassword = rs.getString("password");
                String salt = SaltManager.getSalt(username); // Busca la salt cifrada

                // Si la salt no está cifrada, intenta obtenerla de la base de datos
                if (salt == null) {
                    salt = rs.getString("salt");

                    if (salt != null) {
                        // Migrar la salt al archivo cifrado
                        SaltManager.saveSalt(username, salt);

                        // Opcional: Eliminar la salt de la base de datos
                        try (PreparedStatement deleteSalt = conn.prepareStatement("UPDATE usuarios SET salt = NULL WHERE username = ?")) {
                            deleteSalt.setString(1, username);
                            deleteSalt.executeUpdate();
                        }
                    }
                }

                if (salt != null) {
                    String hashedPassword = hashPassword(password, salt);

                    if (storedPassword.equals(hashedPassword)) {
                        System.out.println("Login exitoso.");
                        return true;
                    } else {
                        System.out.println("Contraseña incorrecta.");
                    }
                } else {
                    System.out.println("No se encontró ninguna salt.");
                }
            } else {
                System.out.println("Usuario no encontrado.");
            }

            return false;

        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    private static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return bytesToHex(salt);
    }

    private static String hashPassword(String password, String salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String combined = password + salt;
            byte[] hash = digest.digest(combined.getBytes());

            for (int i = 0; i < 2; i++) {
                hash = digest.digest(hash);
            }

            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}