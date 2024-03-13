package com.example.server.security.service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.example.server.domain.user.dto.UserDto;
import com.example.server.domain.user.entity.User;
import com.example.server.security.properties.AuthTokenProperties;
import com.example.server.security.utils.JwtAuthUtils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtAuthService {
    public static String createAccessToken(UserDto user, UUID refreshTokenId) {
        return Jwts.builder()
            .setSubject("access_token")
            .setClaims(createAccessTokenClaims(user, refreshTokenId))
            .setExpiration(createTokenExpiration(JwtAuthUtils.ACCESS_TOKEN_VALIDATION_SECOND))
            .signWith(createSigningKey(AuthTokenProperties.getAccessSecret()), SignatureAlgorithm.HS256)
            .compact();
    }

    public static String createRefreshToken(UserDto user) {
        return Jwts.builder()
            .setSubject("refresh_token")
            .setClaims(createRefreshTokenClaims(user))
            .setExpiration(createTokenExpiration(JwtAuthUtils.REFRESH_TOKEN_VALIDATION_SECOND))
            .signWith(createSigningKey(AuthTokenProperties.getRefreshSecret()), SignatureAlgorithm.HS256)
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
    private static Map<String, Object> createAccessTokenClaims(UserDto user, UUID refreshTokenId) {
        Map<String, Object> map = new HashMap<>();
        map.put("username", user.getUsername());
        map.put("refreshTokenId", refreshTokenId);
        return map;
    }

    private static Map<String, Object> createRefreshTokenClaims(UserDto user) {
        Map<String, Object> map = new HashMap<>();
        map.put("username", user.getUsername());
        return map;
    }
}
