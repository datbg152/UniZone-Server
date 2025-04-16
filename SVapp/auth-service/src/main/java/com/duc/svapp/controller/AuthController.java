package com.duc.svapp.controller;

import com.duc.svapp.dto.LoginRequest;
import com.duc.svapp.dto.LogoutRequest;
import com.duc.svapp.dto.RefreshTokenRequest;
import com.duc.svapp.jwt.JwtToken;
import com.duc.svapp.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<JwtToken> login(@RequestBody LoginRequest loginRequest) {
        JwtToken token = authService.login(loginRequest);
        return ResponseEntity.ok(token);
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtToken> refresh(@RequestBody RefreshTokenRequest request) {
        JwtToken newToken = authService.refresh(request.getRefreshToken());
        return ResponseEntity.ok(newToken);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(
            @RequestHeader("Authorization") String authorizationHeader,
            @RequestBody LogoutRequest request) {

        // Extract access token from header
        String accessToken = authorizationHeader.replace("Bearer ", "");

        // Optionally validate or blacklist access token (if real-time logout is needed)
        // For stateless JWT, this step is optional unless you use a blacklist

        // Delete refresh token from Redis
        authService.logout(request.getRefreshToken());

        return ResponseEntity.ok("Logged out successfully");
    }
}