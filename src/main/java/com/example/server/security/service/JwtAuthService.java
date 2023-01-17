package com.example.server.security.service;

import java.security.Key;
import java.util.Date;

import org.springframework.stereotype.Service;

import com.example.server.domain.user.entity.User;
import com.example.server.security.properties.AuthTokenProperties;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtAuthService {
    private static long ACCESS_TOKEN_VALIDATION_SECOND = 1000 * 60 * 15;  // 15분
    private static long REFRESH_TOKEN_VALIDATION_SECOND = 1000 * 60 * 60 * 24 * 5;    // 5일

    public static String createAccessToken(User user) {
        return Jwts.builder()
            .setSubject("access_token")
            .setExpiration(createTokenExpiration(ACCESS_TOKEN_VALIDATION_SECOND))
            .claim("username", user.getUsername())
            .signWith(createSigningKey(AuthTokenProperties.getAccessSecret()), SignatureAlgorithm.HS256)
            .compact();
    }

    public static String createRefreshToken(User user) {
        return Jwts.builder()
            .setSubject("refresh_token")
            .setExpiration(createTokenExpiration(REFRESH_TOKEN_VALIDATION_SECOND))
            .claim("username", user.getUsername())
            .signWith(createSigningKey(AuthTokenProperties.getRefreshSecret()), SignatureAlgorithm.HS256)
            .compact();
    }

    private static Date createTokenExpiration(long expirationTime) {
        Date expiration = new Date(System.currentTimeMillis() + expirationTime);
        return expiration;
    }

    private static Key createSigningKey(String tokenSecret) {
        byte[] keyBytes = Decoders.BASE64.decode(tokenSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
