package com.example.server.security.utils;

public interface JwtAuthUtils {
    // private static long ACCESS_TOKEN_VALIDATION_SECOND = 1000 * 60 * 15;  // 15분
    int ACCESS_TOKEN_VALIDATION_SECOND = 1000 * 30;  // 30초
    // private static long REFRESH_TOKEN_VALIDATION_SECOND = 1000 * 60 * 60 * 24 * 5;    // 5일
    int REFRESH_TOKEN_VALIDATION_SECOND = 1000 * 60 * 5;    // 5분
}
