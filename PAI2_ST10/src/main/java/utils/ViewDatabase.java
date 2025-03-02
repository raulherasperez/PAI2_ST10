package utils;
import java.sql.*;

public class ViewDatabase {
    public static void main(String[] args) {
        viewUsuarios();
        viewTransacciones();
    }

    private static void viewUsuarios() {
        String url = "jdbc:sqlite:usuarios.db";
        
        try (Connection conn = DriverManager.getConnection(url);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT * FROM usuarios")) {
            
            System.out.println("Usuarios:");
            while (rs.next()) {
                System.out.println("ID: " + rs.getInt("id"));
                System.out.println("Username: " + rs.getString("username"));
                System.out.println("Password: " + rs.getString("password"));
                System.out.println("----------------------------");
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    private static void viewTransacciones() {
        String url = "jdbc:sqlite:transacciones.db";
        
        try (Connection conn = DriverManager.getConnection(url);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT * FROM transacciones")) {
            
            System.out.println("Transacciones:");
            while (rs.next()) {
                System.out.println("ID: " + rs.getInt("id"));
                System.out.println("Message: " + rs.getString("message"));
                System.out.println("Nonce: " + rs.getString("nonce"));
                System.out.println("----------------------------");
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }
}
