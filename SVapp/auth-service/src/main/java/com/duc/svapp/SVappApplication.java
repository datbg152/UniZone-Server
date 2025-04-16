package com.duc.svapp;

import jakarta.annotation.PostConstruct;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SVappApplication {

    public static void main(String[] args) {
        SpringApplication.run(SVappApplication.class, args);
    }

    @PostConstruct
    public void printAppUrl() {
        System.out.println("🚀 App is running at: http://localhost:8080/");
    }

}
