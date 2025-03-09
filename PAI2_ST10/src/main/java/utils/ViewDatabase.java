package utils;

import java.sql.*;

public class ViewDatabase {
    public static void main(String[] args) {
        viewUsuarios();
        viewMensajesDiarios();
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
            System.out.println("Error al visualizar usuarios: " + e.getMessage());
        }
    }

    private static void viewMensajesDiarios() {
        String url = "jdbc:sqlite:usuarios.db";

        try (Connection conn = DriverManager.getConnection(url);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT * FROM mensajes_diarios")) {

            System.out.println("Mensajes Diarios:");
            while (rs.next()) {
                System.out.println("ID: " + rs.getInt("id"));
                System.out.println("Username: " + rs.getString("username"));
                System.out.println("Fecha: " + rs.getString("fecha"));
                System.out.println("Cantidad de Mensajes: " + rs.getInt("cantidad_mensajes"));
                System.out.println("----------------------------");
            }
        } catch (SQLException e) {
            System.out.println("Error al visualizar mensajes diarios: " + e.getMessage());
        }
    }
}
