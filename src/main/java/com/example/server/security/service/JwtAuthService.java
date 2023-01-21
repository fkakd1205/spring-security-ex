package com.example.server.security.service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.example.server.domain.user.entity.User;
import com.example.server.security.properties.AuthTokenProperties;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtAuthService {
    // private static long ACCESS_TOKEN_VALIDATION_SECOND = 1000 * 60 * 15;  // 15분
    private static int ACCESS_TOKEN_VALIDATION_SECOND = 1000 * 30;  // 30초
    // private static long REFRESH_TOKEN_VALIDATION_SECOND = 1000 * 60 * 60 * 24 * 5;    // 5일
    private static int REFRESH_TOKEN_VALIDATION_SECOND = 1000 * 60 * 5;    // 5분

    public static String createAccessToken(User user, UUID refreshTokenId) {
        return Jwts.builder()
            .setSubject("access_token")
            .setClaims(createAccessTokenClaims(user, refreshTokenId))
            .setExpiration(createTokenExpiration(ACCESS_TOKEN_VALIDATION_SECOND))
            .signWith(createSigningKey(AuthTokenProperties.getAccessSecret()), SignatureAlgorithm.HS256)
            .compact();
    }

    public static String createRefreshToken(User user) {
        return Jwts.builder()
            .setSubject("refresh_token")
            .setClaims(createRefreshTokenClaims(user))
            .signWith(createSigningKey(AuthTokenProperties.getRefreshSecret()), SignatureAlgorithm.HS256)
            .setExpiration(createTokenExpiration(REFRESH_TOKEN_VALIDATION_SECOND))
            .compact();
    }

    private static Date createTokenExpiration(int expirationTime) {
        Date expiration = new Date(System.currentTimeMillis() + expirationTime);
        return expiration;
    }

    private static Key createSigningKey(String tokenSecret) {
        byte[] keyBytes = Decoders.BASE64.decode(tokenSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // 인가 필터 - access token 만료 시 refresh token의 유효성을 쉽게 조회하기 위해 refresh token id도 함께 넣어준다
    private static Map<String, Object> createAccessTokenClaims(User user, UUID refreshTokenId) {
        Map<String, Object> map = new HashMap<>();
        map.put("username", user.getUsername());
        map.put("refreshTokenId", refreshTokenId);
        return map;
    }

    private static Map<String, Object> createRefreshTokenClaims(User user) {
        Map<String, Object> map = new HashMap<>();
        map.put("username", user.getUsername());
        return map;
    }
}
