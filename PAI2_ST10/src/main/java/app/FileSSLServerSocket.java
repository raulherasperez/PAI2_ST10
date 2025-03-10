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
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
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
                        System.out.println("Cliente desconectado.");
                        break;
                    }
        
                    System.out.println("Acción recibida: " + action);
        
                    String userName = input.readLine();
                    if (userName == null || userName.isEmpty()) {
                        output.println("Error: Usuario no identificado.");
                        continue;
                    }
                    System.out.println("Usuario: " + userName);
        
                    if ("register".equals(action)) {
                        String password = input.readLine();
                        output.println(registerUser(userName, password) ? "Registro exitoso." : "Error: El usuario ya existe.");
                    } else if ("login".equals(action)) {
                        String password = input.readLine();
                        if (loginUser(userName, password)) {
                            output.println("Login Successful");
                        } else {
                            output.println("Error: Usuario o contraseña incorrectos.");
                        }
                    } else if ("logout".equals(action)) {
                        output.println("Cerrando sesión...");
                        connected = false;
                    } else if ("sendMessage".equals(action)) {
                        String message = input.readLine();
                        if (message == null || message.isEmpty()) {
                            output.println("Error: El mensaje no puede estar vacío.");
                            continue;
                        }
        
                        System.out.println("Mensaje recibido de " + userName + ": " + message);
                        incrementMessageCount(userName); // Incrementar mensajes en la BD
                        output.println("Mensaje registrado correctamente.");
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
                createMessagesDailyTable(conn);

                // Verificar si los usuarios de prueba existen, y si no, crearlos
                createTestUserIfNotExist("test1", "test_1", conn);
                createTestUserIfNotExist("test2", "test_2", conn);
                createTestUserIfNotExist("test3", "test_3", conn);

                System.err.println("Base de datos y usuarios de prueba creados exitosamente.");
            } else {
                System.err.println("La base de datos ya existe.");

                // Si la base de datos ya existe, verificamos si los usuarios de prueba existen y los creamos si no
                createUsersTable(conn); // Crear la tabla si no existe
                createMessagesDailyTable(conn);
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
            return;
        }
        }

        private static void incrementMessageCount(String username) {
            try (Connection conn = DriverManager.getConnection(DB_URL)) {
                conn.setAutoCommit(true); // Asegúrate de que los cambios se guardan automáticamente
        
                System.out.println("Incrementando contador de mensajes para: " + username);
        
                // Verificar la fecha actual según SQLite
                ResultSet dateTest = conn.createStatement().executeQuery("SELECT DATE('now')");
                if (dateTest.next()) {
                    System.out.println("Fecha actual según SQLite: " + dateTest.getString(1));
                }
        
                // Verificar si ya existe un registro para el usuario en la fecha actual
                String sqlCheck = "SELECT cantidad_mensajes FROM mensajes_diarios WHERE username = ? AND fecha = DATE('now')";
                try (PreparedStatement pstmtCheck = conn.prepareStatement(sqlCheck)) {
                    pstmtCheck.setString(1, username);
                    ResultSet rs = pstmtCheck.executeQuery();
        
                    if (rs.next()) {
                        // Si ya existe, incrementamos el contador
                        int currentCount = rs.getInt("cantidad_mensajes");
                        System.out.println("Mensajes actuales para " + username + ": " + currentCount);
        
                        String sqlUpdate = "UPDATE mensajes_diarios SET cantidad_mensajes = ? WHERE username = ? AND fecha = DATE('now')";
                        try (PreparedStatement pstmtUpdate = conn.prepareStatement(sqlUpdate)) {
                            pstmtUpdate.setInt(1, currentCount + 1);
                            pstmtUpdate.setString(2, username);
                            int rowsUpdated = pstmtUpdate.executeUpdate();
                            System.out.println("Filas actualizadas: " + rowsUpdated);
                        }
                    } else {
                        // Si no existe, insertamos un nuevo registro
                        System.out.println("No existe un registro previo. Creando uno nuevo...");
                        String sqlInsert = "INSERT INTO mensajes_diarios (username, fecha, cantidad_mensajes) VALUES (?, DATE('now'), 1)";
                        try (PreparedStatement pstmtInsert = conn.prepareStatement(sqlInsert)) {
                            pstmtInsert.setString(1, username);
                            int rowsInserted = pstmtInsert.executeUpdate();
                            System.out.println("Filas insertadas: " + rowsInserted);
                        }
                    }
                }
        
                // Comprobar la tabla después de la operación
                ResultSet rsCheck = conn.createStatement().executeQuery("SELECT * FROM mensajes_diarios");
                System.out.println("Contenido actual de la tabla mensajes_diarios:");
                while (rsCheck.next()) {
                    System.out.println("Usuario: " + rsCheck.getString("username") + 
                                       ", Fecha: " + rsCheck.getString("fecha") + 
                                       ", Cantidad de mensajes: " + rsCheck.getInt("cantidad_mensajes"));
                }
        
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        
}