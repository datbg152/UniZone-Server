package com.duc.svapp.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @Column(name = "student_id")
    private String studentId;

    private String studentName;

    @Column(unique = true)
    private String email;

    private String password;

    private String role;
}