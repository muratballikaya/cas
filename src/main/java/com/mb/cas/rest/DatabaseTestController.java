package com.mb.cas.rest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.sql.Connection;

@RestController
public class DatabaseTestController {

    @Autowired
    private DataSource dataSource;

    @GetMapping("/test-db")
    public String testDatabaseConnection() {
        try (Connection connection = dataSource.getConnection()) {
            return "Connected to database: " + connection.getCatalog();
        } catch (Exception e) {
            return "Database connection failed: " + e.getMessage();
        }
    }
}
