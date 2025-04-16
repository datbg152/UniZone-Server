package com.duc.svapp.jwt;

import com.duc.svapp.dto.UserDto;
import com.duc.svapp.exception.ApiException;
import com.duc.svapp.exception.ExceptionEnum;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j // 롬복을 이용하여 로깅을 위한 Logger 선언
@Component
public class JwtTokenProvider {

    private final Key key; // JWT 서명을 위한 Key 객체 선언

    @Autowired
    private RefreshTokenInfoRepository refreshTokenInfoRepository;
    //private RefreshTokenInfoRedisRepository refreshTokenInfoRepository; // RefreshToken 정보를 저장하기 위한 Repository

    // 생성자를 통한 JWT 서명용 Key 초기화
    // application.property에서 secret 값 가져와서 key에 저장
    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey); // Base64로 인코딩된 Secret Key 디코딩
        this.key = Keys.hmacShaKeyFor(keyBytes); // Secret Key를 이용하여 Key 객체 생성
    }

    // 유저 정보를 이용하여 AccessToken과 RefreshToken을 생성하는 메서드
    public JwtToken generateToken(Authentication authentication) {
        // 권한 가져오기
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime(); // 현재 시각 가져오기
        Date issuedAt = new Date(); // 토큰 발급 시각

        //Header 부분 설정
        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "HS256");
        headers.put("typ", "JWT");

        // Access Token 생성
        String accessToken = Jwts.builder()
                .setHeader(createHeaders()) // Header 부분 설정
                .setSubject("accessToken") // 토큰 주제 설정
                .claim("iss", "off") // 토큰 발급자 설정
                .claim("aud", authentication.getName()) // 토큰 대상자 설정
                .claim("auth", authorities) // 사용자 권한 설정
                .setExpiration(new Date(now + 1800000)) // 토큰 만료 시간 설정 (30분)
                .setIssuedAt(issuedAt) // 토큰 발급 시각 설정
                .signWith(key, SignatureAlgorithm.HS256) // 서명 알고리즘 설정
                .compact(); // 토큰 생성

        // Refresh Token 생성
        String refreshToken = Jwts.builder()
                .setHeader(createHeaders()) // Header 부분 설정
                .setSubject("refreshToken") // 토큰 주제 설정
                .claim("iss", "off") // 토큰 발급자 설정
                .claim("aud", authentication.getName()) // 토큰 대상자 설정
                .claim("auth", authorities) // 사용자 권한 설정
                .claim("add", "ref") // 추가 정보 설정
                .setExpiration(new Date(now + 604800000)) // 토큰 만료 시간 설정 (7일)
                .setIssuedAt(issuedAt) // 토큰 발급 시각 설정
                .signWith(key, SignatureAlgorithm.HS256) // 서명 알고리즘 설정
                .compact(); // 토큰 생성

        // TokenInfo 객체 생성 및 반환
        return JwtToken.builder()
                .grantType("Bearer") // 토큰 타입 설정
                .accessToken(accessToken) // Access Token 설정
                .refreshToken(refreshToken) // Refresh Token 설정
                .build(); // TokenInfo 객체 생성
    }

    // JWT 토큰을 복호화하여 토큰에 들어있는 정보를 꺼내 Authentication 객체를 생성하는 메서드
    public Authentication getAuthentication(String token) {
        // Jwt 토큰 복호화
        Claims claims = parseClaims(token);

        if (claims.get("auth") == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        // 클레임에서 권한 가져오기
        Collection<? extends GrantedAuthority> authorities = Arrays.stream(claims.get("auth").toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        // UserDetails 객체를 만들어서 Authentication return
        // UserDetails: interface, User: UserDetails를 구현한 class
        UserDetails principal = new User((String) claims.get("aud"), "", authorities);

        // UsernamePasswordAuthenticationToken 객체 반환
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    // JWT 토큰의 유효성을 검증하는 메서드
    public Map<Boolean, String> validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token); // kiểm tra hợp lệ
            return Map.of(true, "success");
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.warn("잘못된 JWT 서명입니다.");
            return Map.of(false, "invalid_signature");
        } catch (ExpiredJwtException e) {
            log.warn("만료된 JWT 토큰입니다.");
            return Map.of(false, "expired");
        } catch (UnsupportedJwtException | IllegalArgumentException e) {
            log.warn("지원되지 않는 JWT 토큰입니다.");
            return Map.of(false, "unsupported_or_illegal");
        } catch (Exception e) {
            log.warn("알 수 없는 JWT 오류");
            return Map.of(false, "unknown_error");
        }
    }

    // RefreshToken을 이용하여 AccessToken을 재발급하는 메서드
    // RefreshToken을 Redis에 저장하는 메서드
    public void saveToken(JwtToken token, Authentication authentication) {
        RefreshTokenInfo info = new RefreshTokenInfo();
        info.setStudentId(authentication.getName());
        info.setRefreshToken(token.getRefreshToken());
        info.setExpiration(7 * 24 * 60 * 60L); // Set TTL to 7 days
        System.out.println("🔥 Saving to Redis: " + info.getRefreshToken());

        refreshTokenInfoRepository.save(info);
    }
    public JwtToken refreshToken(String refreshToken) {
        try {
            // Refresh Token 복호화
            Authentication authentication = getAuthentication(refreshToken);
            // Redis에 저장된 Refresh Token 정보 가져오기

            RefreshTokenInfo redisRefreshTokenInfo = refreshTokenInfoRepository.findById(authentication.getName()).orElseThrow();

            JwtToken refreshGetToken = null;
            // Redis에 저장된 Refresh Token과 요청된 Refresh Token이 일치할 경우
            if (refreshToken.equals(redisRefreshTokenInfo.getRefreshToken())) {
                refreshGetToken = generateToken(authentication); // 토큰 재발급

                saveToken(refreshGetToken, authentication); // Redis에 새로운 Refresh Token 정보 저장
                return refreshGetToken; // 새로운 토큰 반환
            } else {
                log.warn("does not exist Token"); // Redis에 저장된 Refresh Token이 존재하지 않을 경우
                throw new ApiException(ExceptionEnum.TOKEN_DOES_NOT_EXIST); // 해당 예외 처리
            }
        } catch (NullPointerException e) {
            log.warn("does not exist Token"); // Refresh Token이 존재하지 않을 경우
            throw new ApiException(ExceptionEnum.TOKEN_DOES_NOT_EXIST); // 해당 예외 처리
        } catch (SignatureException e) {
            log.warn("Invalid Token Info"); // 토큰 정보가 잘못된 경우
            throw new ApiException(ExceptionEnum.INVALID_TOKEN_INFO); // 해당 예외 처리
        } catch (NoSuchElementException e) {
            log.warn("no such Token value"); // Redis에 해당 토큰이 존재하지 않을 경우
            throw new ApiException(ExceptionEnum.TOKEN_DOES_NOT_EXIST); // 해당 예외 처리
        }
    }

    // JWT 토큰을 파싱하여 클레임 정보를 반환하는 메서드
    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody(); // 토큰 파싱하여 클레임 정보 반환
        } catch (ExpiredJwtException e) {
            return e.getClaims(); // 만료된 토큰의 경우 클레임 정보 반환
        }
    }

    // JWT 토큰의 Header 정보를 생성하는 메서드
    private static Map<String, Object> createHeaders() {
        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "HS256"); // 알고리즘 정보 설정
        headers.put("typ", "JWT"); // 토큰 타입 정보 설정
        return headers; // 생성된 Header 정보 반환
    }
    public String getHeaderToken(String headerName, HttpServletRequest request) {
        String header = request.getHeader(headerName);
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }

    public UserDto checkUser(String token) {
        Claims claims = parseClaims(token);

        String username = claims.get("aud", String.class);
        String roles = claims.get("auth", String.class);

        return UserDto.builder()
                .studentId(username)
                .roles(roles)
                .build();
    }

    public RefreshTokenInfo checkRefresh(String refreshToken) {
        // Lấy authentication từ refreshToken
        Authentication authentication = getAuthentication(refreshToken);
        String studentID = authentication.getName(); // note: changed token as PK

        // Lấy refreshToken từ Redis và kiểm tra khớp
        RefreshTokenInfo storedTokenInfo = refreshTokenInfoRepository.findById(studentID).orElse(null);

        if (storedTokenInfo != null && storedTokenInfo.getRefreshToken().equals(refreshToken)) {
            return storedTokenInfo;
        }

        return null; // Không hợp lệ
    }

    public void deleteToken(String refreshToken) {
        Authentication authentication = getAuthentication(refreshToken);
        String username = authentication.getName();

        refreshTokenInfoRepository.deleteById(username);
    }
    public String createAccessToken(String studentId) {
        long now = (new Date()).getTime();
        Date issuedAt = new Date();

        String role = "USER"; // bạn có thể truyền role nếu cần thiết

        return Jwts.builder()
                .setHeader(createHeaders())
                .setSubject("accessToken")
                .claim("iss", "off")
                .claim("aud", studentId)
                .claim("auth", role)
                .setExpiration(new Date(now + 1800000)) // 30 phút
                .setIssuedAt(issuedAt)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
}