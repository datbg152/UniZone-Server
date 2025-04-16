package com.duc.svapp.service;

import com.duc.svapp.entity.User;
import com.duc.svapp.repository.UserRepository;
import com.opencsv.CSVReader;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

@Service
public class UserDataLoader {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostConstruct
    public void loadUsersFromCSV() throws Exception {
        var stream = getClass().getClassLoader().getResourceAsStream("UserData.csv");

        if (stream != null) {
            InputStreamReader input = new InputStreamReader(stream);
            CSVReader reader = new CSVReader(input);

            List<String[]> rows = reader.readAll();
            rows.remove(0); // ignore header

            List<User> users = new ArrayList<>();
            for (String[] row : rows) {
                String encodedPassword = passwordEncoder.encode(row[4]); // hash password "1234567"
                users.add(new User(row[0], row[1], row[2], row[3], encodedPassword));
            }

            //userRepository.deleteAll();
            userRepository.saveAll(users);
            System.out.println("✅ User data loaded & password hashed.");
        } else {
            System.out.println("ℹ️ CSV file not found. Skipping data load.");
        }
    }
}