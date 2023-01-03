package com.example.server.config.auth;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.example.server.domain.user.entity.User;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public JwtAuthenticationFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        
        // form으로 넘어온 값으로 user 객체를 생성
        User user = new ObjectMapper().readValue(request.getReader(), User.class);
        UsernamePasswordAuthenticationToken userToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
        
        // AuthenticationManager에 인증 위임
        return getAuthenticationManager().authenticate(userToken);
    }

    @Override
    protected AuthenticationFailureHandler getFailureHandler() {
        // TODO Auto-generated method stub
        return super.getFailureHandler();
    }

    @Override
    protected AuthenticationSuccessHandler getSuccessHandler() {
        // TODO Auto-generated method stub
        return super.getSuccessHandler();
    }
}
