package com.duc.svapp.jwt;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

@Getter
@Setter
@RedisHash("refreshTokenInfo")
public class RefreshTokenInfo {
    @Id
    private String refreshToken;
    private String studentId;

    @TimeToLive
    private Long expiration;

}