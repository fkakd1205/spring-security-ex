package com.example.server.security.handler;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import com.example.server.domain.refresh_token.entity.RefreshToken;
import com.example.server.domain.refresh_token.repository.RefreshTokenRepository;
import com.example.server.domain.user.dto.UserDto;
import com.example.server.security.auth.CustomUserDetails;
import com.example.server.security.service.JwtAuthService;

public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private RefreshTokenRepository refreshTokenRepository;

    @Value("${app.oauth2.authorized-redirect-url}")
    private String authorizedRedirectUrl;

    public OAuth2AuthenticationSuccessHandler(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        System.out.println("-----successfulOAuthAuthorization-----");

         // 1. 로그인 성공된 user 조회
        UserDto user = ((CustomUserDetails) authentication.getPrincipal()).getUser();

        // 2. Access Token 생성, Refresh Token 생성
        UUID refreshTokenId = UUID.randomUUID();
        String accessToken = JwtAuthService.createAccessToken(user, refreshTokenId);
        String refreshToken = JwtAuthService.createRefreshToken(user);

        // 3. Refresh Token DB 저장
        // 이미 존재하는 refresh token이 있다면 제거 후 생성
        try{
            Optional<RefreshToken> refreshTokenOpt = refreshTokenRepository.findByUserId(user.getId());

            if(refreshTokenOpt.isPresent()) {
                refreshTokenRepository.delete(refreshTokenOpt.get());
            }

            RefreshToken newRefreshToken = RefreshToken.builder()
                .id(refreshTokenId)
                .refreshToken(refreshToken)
                .createdAt(LocalDateTime.now())
                .userId(user.getId())
                .build();

            refreshTokenRepository.save(newRefreshToken);
        }catch(NullPointerException e) {
            throw new AuthenticationServiceException("유효하지 않은 사용자입니다.");
        }

        // 4. Cookie에 Access Token (access_token) 주입
        ResponseCookie cookies = ResponseCookie.from("access_token", accessToken)
            .httpOnly(true)
            .domain("localhost")
            // .secure(true)
            .sameSite("Strict")
            .path("/")
            .maxAge(3 * 24 * 60 * 60)     // 3일
            .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookies.toString());
        
        this.clearAuthenticationAttributes(request);
        this.getRedirectStrategy().sendRedirect(request, response, authorizedRedirectUrl);
    }
}
