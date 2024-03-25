package com.example.server.security.auth;

import java.io.IOException;
import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.example.server.domain.refresh_token.entity.RefreshToken;
import com.example.server.domain.refresh_token.repository.RefreshTokenRepository;
import com.example.server.domain.user.dto.UserDto;
import com.example.server.domain.user.entity.User;
import com.example.server.domain.user.repository.UserRepository;
import com.example.server.security.properties.AuthTokenProperties;
import com.example.server.security.service.JwtAuthService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private UserRepository userRepository;
    private RefreshTokenRepository refreshTokenRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository, RefreshTokenRepository refreshTokenRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    // 1. access 토큰을 담고 있는 쿠키를 확인
    // 2. access 토큰이 유효하다면 -> 인증된 객체 저장하고 doFilter, 그렇지 않다면 -> refresh 토큰 검사
    // 3. DB에서 refresh 토큰 조회. refresh 토큰이 유효하다면 -> 새로운 access 토큰 발급, 그렇지 않다면 -> 인증된 객체를 저장하지 않고 doFilter
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        System.out.println("#=====AUTHORIZATION FILTER=====#");

        Cookie cookie = null;
        try {
            cookie = Arrays.stream(request.getCookies())
                    .filter(r -> r.getName().equals("access_token"))
                    .findAny()
                    .orElse(null);
        } catch (NullPointerException e) {
            filterChain.doFilter(request, response);
            return;
        }

        if (cookie == null) {
            filterChain.doFilter(request, response);
            return;
        }

        String accessToken = cookie.getValue();
        Claims claims = null;
        boolean isAccessTokenExpired = false;
        
        try {
            claims = Jwts.parserBuilder().setSigningKey(AuthTokenProperties.getAccessSecret()).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            System.out.println("-----access token expired-----");
            claims = e.getClaims();
            isAccessTokenExpired = true;
        } catch (MalformedJwtException e) {
            filterChain.doFilter(request, response);
            return;
        } catch (Exception e) {
            filterChain.doFilter(request, response);
            return;
        }

        // 토큰에 저장된 유저정보가 존재하지 않는 경우 예외처리
        User savedUser = userRepository.findByUsername(claims.get("username").toString())
            .orElseThrow(() -> new UserPrincipalNotFoundException("not found user."));
        UserDto savedUserDto = UserDto.toDto(savedUser);

        // 액세스토큰이 만료된 경우
        if(isAccessTokenExpired) {
            UUID refreshTokenId = UUID.fromString(claims.get("refreshTokenId").toString());
            Optional<RefreshToken> refreshTokenOpt = refreshTokenRepository.findById(refreshTokenId);

            // 액세스토큰과 매칭된 리프레시토큰을 DB에서 조회한다
            if(refreshTokenOpt.isPresent()) {
                Claims refreshTokenClaims = null;
                String refreshToken = refreshTokenOpt.get().getRefreshToken();

                try {
                    refreshTokenClaims = Jwts.parserBuilder().setSigningKey(AuthTokenProperties.getRefreshSecret()).build().parseClaimsJws(refreshToken).getBody();
                } catch (ExpiredJwtException e) {
                    // 리프레시 토큰이 만료된 경우
                    System.out.println("-----refresh token expired-----");
                    
                    // 만료된 리프레시 토큰을 제거 후 doFitler
                    refreshTokenRepository.delete(refreshTokenOpt.get());
                    filterChain.doFilter(request, response);
                    return;
                } catch (MalformedJwtException e) {
                    filterChain.doFilter(request, response);
                    return;
                } catch (Exception e) {     // TODO :: 구체 예외 처리
                    filterChain.doFilter(request, response);
                    return;
                }

                // 리프레시 토큰이 존재한다면 액세스토큰 발급
                String newAccessToken = JwtAuthService.createAccessToken(savedUserDto, refreshTokenId);

                if(refreshTokenClaims != null) {
                    ResponseCookie cookies = ResponseCookie.from("access_token", newAccessToken)
                        .httpOnly(true)
                        .domain("localhost")
                        // .secure(true)
                        .sameSite("Strict")
                        .path("/")
                        .maxAge(3 * 24 * 60 * 60)     // 3일
                        .build();

                    response.addHeader(HttpHeaders.SET_COOKIE, cookies.toString());
                }
            }else {
                System.out.println("-----not found refresh token-----");

                filterChain.doFilter(request, response);
                return;
            }
        }

        this.saveAuthenticationToSecurityContextHolder(savedUserDto);
        filterChain.doFilter(request, response);
    }

    private void saveAuthenticationToSecurityContextHolder(UserDto user) {
        CustomUserDetails userDetails = new CustomUserDetails(user);

        // 인가 처리가 정상적으로 완료된다면 Authentication 객체 생성
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
