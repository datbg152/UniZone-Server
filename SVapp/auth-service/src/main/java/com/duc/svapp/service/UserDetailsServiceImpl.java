package com.duc.svapp.service;

import com.duc.svapp.entity.User;
import com.duc.svapp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@RequiredArgsConstructor
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String studentId) throws UsernameNotFoundException {
        User user = userRepository.findByStudentId(studentId).orElse(null);

        if (user == null) {
            throw new UsernameNotFoundException("User not found with studentId: " + studentId);
        }
        System.out.println(">> DB password: " + user.getPassword());
        System.out.println(">> Student ID: " + user.getStudentId());

        return new org.springframework.security.core.userdetails.User(
                user.getStudentId(),                    // username
                user.getPassword(),                 // password
                Collections.singletonList(          // authorities
                        new SimpleGrantedAuthority(user.getRole())
                )
        );
    }
}