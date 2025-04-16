package com.duc.svapp.jwt;

import com.duc.svapp.dto.UserDto;
import com.duc.svapp.jwt.JwtTokenProvider;
import com.duc.svapp.jwt.RefreshTokenInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtProvider;

    @Value("${AUTHORIZATION_HEADER}")
    private String AUTHORIZATION_HEADER;

    @Value("${REAUTHORIZATION_HEADER}")
    private String REAUTHORIZATION_HEADER;

    @Value("${ADMIN_HEADER}")
    private String ADMINAUTHORIZATION_HEADER;

    @Value("${jwt.token-prefix}")
    private String tokenPrefix;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        System.out.println("▶️ AUTH HEADER: " + request.getHeader(AUTHORIZATION_HEADER));
        System.out.println("▶️ Method: " + request.getMethod());

        String requestURI = request.getRequestURI();

        // OPTIONS or /auth → skip filter

        if (request.getMethod().equals("OPTIONS") ||
                requestURI.equals("/auth/login") ||
                requestURI.equals("/auth/logout") ||
                requestURI.equals("/auth/refresh")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Admin route
        if (requestURI.startsWith("/admin") &&
                !requestURI.equals("/admin/login") &&
                !requestURI.startsWith("/admin/logout")) {

            String adminToken = jwtProvider.getHeaderToken(ADMINAUTHORIZATION_HEADER, request);
            Map<Boolean, String> accessResult = jwtProvider.validateToken(adminToken);

            if (accessResult.isEmpty() || !accessResult.containsKey(true)) {
                response.sendError(403);
                return;
            }

            UserDto user = jwtProvider.checkUser(adminToken);
            if (!"ADMIN".equals(user.getRoles())) {
                response.sendError(404);
                return;
            }

            setAuthentication(user);
            response.setHeader(ADMINAUTHORIZATION_HEADER, tokenPrefix + adminToken);
            filterChain.doFilter(request, response);
            return;
        }

        // User route
        String accessToken = jwtProvider.getHeaderToken(AUTHORIZATION_HEADER, request);
        String refreshToken = jwtProvider.getHeaderToken(REAUTHORIZATION_HEADER, request);

        if (accessToken == null) {
            response.sendError(403);
            return;
        }

        Map<Boolean, String> accessResult = jwtProvider.validateToken(accessToken);
        if (accessResult.containsKey(true) && "success".equals(accessResult.get(true))) {
            UserDto user = jwtProvider.checkUser(accessToken);
            setAuthentication(user);

            response.setHeader(AUTHORIZATION_HEADER, tokenPrefix + accessToken);
            response.setHeader(REAUTHORIZATION_HEADER, tokenPrefix + refreshToken);
        } else {
            // Token hết hạn → kiểm tra refresh
            if (refreshToken == null) {
                response.sendError(403);
                return;
            }

            RefreshTokenInfo checkRefresh = jwtProvider.checkRefresh(refreshToken);
            if (checkRefresh == null) {
                response.sendError(403);
                return;
            }

            Map<Boolean, String> refreshResult = jwtProvider.validateToken(refreshToken);
            if (refreshResult.isEmpty() || !refreshResult.containsKey(true)
                    || !"success".equals(refreshResult.get(true))) {
                jwtProvider.deleteToken(refreshToken);
                response.sendError(403);
                return;
            }

            String newAccessToken = jwtProvider.createAccessToken(checkRefresh.getStudentId());
            UserDto user = jwtProvider.checkUser(newAccessToken);
            setAuthentication(user);

            response.setHeader(AUTHORIZATION_HEADER, tokenPrefix + newAccessToken);
            response.setHeader(REAUTHORIZATION_HEADER, tokenPrefix + refreshToken);
        }

        filterChain.doFilter(request, response);
    }

    private void setAuthentication(UserDto userDto) {
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDto,
                null,
                Collections.singletonList(new SimpleGrantedAuthority(userDto.getRoles()))
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}