package com.example.server.security.auth;

import java.util.UUID;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JwtAuthenticationProvider implements AuthenticationProvider {
    private final CustomUserDetailsService customUserDetailsService;
    private final BCryptPasswordEncoder passwordEncoder;

    // 실제 인증을 담당
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        System.out.println("#=====AUTHENTICATION PROVIDER=====#");
        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;

        String username = token.getName();
        String password = token.getCredentials().toString();

        CustomUserDetails savedUser = (CustomUserDetails) customUserDetailsService.loadUserByUsername(username);
        UUID salt = savedUser.getUser().getSalt();

        // salt된 password를 구한다
        String saltedPassword = password + salt;

        if(!passwordEncoder.matches(saltedPassword, savedUser.getPassword())) {
            throw new BadCredentialsException("로그인 정보가 올바르지 않습니다.");
        }
    
        // 인증 완료된 객체 생성
        return new UsernamePasswordAuthenticationToken(savedUser, password, savedUser.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
    
}
