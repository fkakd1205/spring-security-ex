package com.example.server.security.auth;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.server.domain.message.Message;
import com.example.server.domain.refresh_token.entity.RefreshToken;
import com.example.server.domain.refresh_token.repository.RefreshTokenRepository;
import com.example.server.security.properties.AuthTokenProperties;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;

public class JwtAuthorizationFilter extends OncePerRequestFilter {
    private RefreshTokenRepository refreshTokenRepository;

    public JwtAuthorizationFilter(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        System.out.println("#=====AUTHORIZATION FILTER=====#");

        Cookie cookie = Arrays.stream(request.getCookies())
            .filter(r -> r.getName().equals("access_token"))
            .findAny()
            .orElse(null);
        
        String accessToken = cookie.getValue();
        Claims claims = null;
        boolean isAccessTokenExpired = false;
        
        try {
            claims = Jwts.parserBuilder().setSigningKey(AuthTokenProperties.getAccessSecret()).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            System.out.println("-----access token expired-----");
            claims = e.getClaims();
            isAccessTokenExpired = true;
        } catch (Exception e) {
            // TODO
        }

        // TODO :: 리프레시 토큰 만료된 경우 처리
        // 액세스토큰이 만료된 경우
        if(isAccessTokenExpired) {
            UUID refreshTokenId = UUID.fromString(claims.get("refreshTokenId").toString());
            Optional<RefreshToken> refreshTokenOpt = refreshTokenRepository.findById(refreshTokenId);
            
            if(refreshTokenOpt.isPresent()) {
                Claims refreshTokenClaims = null;
                String refreshToken = refreshTokenOpt.get().getRefreshToken();

                try {
                    refreshTokenClaims = Jwts.parserBuilder().setSigningKey(AuthTokenProperties.getRefreshSecret()).build().parseClaimsJws(refreshToken).getBody();
                } catch (ExpiredJwtException e) {
                    // 리프레시 토큰이 만료된 경우
                    System.out.println("-----refresh token expired-----");
                    refreshTokenRepository.delete(refreshTokenOpt.get());
                } catch (Exception e) {
                    // TODO
                }

                // 리프레시 토큰이 존재한다면 액세스토큰 발급
                if(refreshTokenClaims != null) {
                    ResponseCookie cookies = ResponseCookie.from("access_token", accessToken)
                        .httpOnly(true)
                        .domain("localhost")
                        // .secure(true)
                        .sameSite("Strict")
                        .path("/")
                        .maxAge(3 * 24 * 60 * 60)     // 3일
                        .build();

                    response.addHeader(HttpHeaders.SET_COOKIE, cookies.toString());

                    // 로그인 성공 response 세팅
                    Message message = new Message();
                    message.setStatus(HttpStatus.OK);
                    message.setMessage("success");
                    message.setMemo("login_success");

                    response.setStatus(HttpStatus.OK.value());
                    response.setContentType(MediaType.APPLICATION_JSON.toString());    
                    new ObjectMapper().writeValue(response.getOutputStream(), message);
                }
            }else {
                // TODO :: 인가 거절
            }
        }

        // filterChain.doFilter(request, response);
    }
}
