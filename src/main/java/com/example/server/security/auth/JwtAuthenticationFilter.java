package com.example.server.security.auth;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.server.domain.user.entity.User;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    public JwtAuthenticationFilter() {
        // form 로그인이 아닌 커스텀 로그인에서 api 요청시 인증 필터를 진행할 url
        setFilterProcessesUrl("/api/v1/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        System.out.println("#=====AUTHENTICATION FILTER=====#");

        try {
            // form으로 넘어온 값으로 user 객체를 생성
            User user = new ObjectMapper().readValue(request.getReader(), User.class);
            UsernamePasswordAuthenticationToken userToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            this.setDetails(request, userToken);

            // AuthenticationManager에 인증 위임
            return getAuthenticationManager().authenticate(userToken);
        } catch (IOException e) {
            throw new AuthenticationServiceException("올바른 아이디와 비밀번호를 입력해주세요.");
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException {
        System.out.println("-----successfulAuthnentication-----");
        // super.successfulAuthentication(request, response, chain, authResult);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {
        System.out.println("-----unsuccessfulAuthnentication-----");
        // super.unsuccessfulAuthentication(request, response, failed);
    }
}
