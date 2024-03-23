package com.example.server.security.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Value("${app.oauth2.unauthorized-redirect-url}")
    private String unauthorizedRedirectUrl;

    @Override
    public void onAuthenticationFailure(final HttpServletRequest request, final HttpServletResponse response,
            final AuthenticationException exception) throws IOException, ServletException {
        System.out.println("-----failureOAuth2Authorization-----");

        // Cookie에 Access Token (access_token) 제거
        ResponseCookie cookies = ResponseCookie.from("access_token", null)
            .httpOnly(true)
            .domain("localhost")
            .sameSite("Strict")
            .path("/")
            .maxAge(0)
            .build();
            
        response.addHeader(HttpHeaders.SET_COOKIE, cookies.toString());
        this.getRedirectStrategy().sendRedirect(request, response, unauthorizedRedirectUrl);
        
    }
}
