package com.example.server.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import com.example.server.domain.refresh_token.repository.RefreshTokenRepository;
import com.example.server.domain.user.repository.UserRepository;
import com.example.server.security.auth.CustomUserDetailsService;
import com.example.server.security.auth.JwtAuthenticationFilter;
import com.example.server.security.auth.JwtAuthenticationProvider;
import com.example.server.security.auth.JwtAuthorizationFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final CustomUserDetailsService customUserDetailsService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        AuthenticationManager authenticationManager = authenticationManager(http.getSharedObject(AuthenticationConfiguration.class));
        JwtAuthenticationFilter jwtAuthenticationFilter = jwtAuthenticationFilter(authenticationManager);
        JwtAuthorizationFilter jwtAuthorizationFilter = jwtAuthorizationFilter(authenticationManager);

        http
            .cors().disable()
            .csrf().disable()
            .formLogin().disable()
            .httpBasic().disable()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS);    // jwt사용으로 세션관리 해제
            // .usernameParameter("uesrname")      // form login에서 왜 uesrname으로 넘어올까..
            // .passwordParameter("password")
            // .permitAll()
            // .loginProcessingUrl("/api/v1/login")
            // .defaultSuccessUrl("/");
        
        http
            .headers().frameOptions().sameOrigin();

        http
                .authorizeRequests()
                .antMatchers("/api/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .antMatchers("/api/test/**")
                .access("hasRole('ROLE_USER')")
                .anyRequest().permitAll();

        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterAfter(jwtAuthorizationFilter, JwtAuthenticationFilter.class);
        
        return http.build();
    }
    
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtAuthenticationProvider jwtAuthenticationProvider() throws Exception {
        return new JwtAuthenticationProvider(customUserDetailsService, passwordEncoder());
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        JwtAuthenticationFilter authenticationFilter = new JwtAuthenticationFilter(refreshTokenRepository);
        authenticationFilter.setAuthenticationManager(authenticationManager);

        SecurityContextRepository contextRepository = new HttpSessionSecurityContextRepository();
        authenticationFilter.setSecurityContextRepository(contextRepository);

        return authenticationFilter;
    }

    @Bean
    public JwtAuthorizationFilter jwtAuthorizationFilter(AuthenticationManager authenticationManager) {
        JwtAuthorizationFilter authorizationFilter = new JwtAuthorizationFilter(authenticationManager, userRepository, refreshTokenRepository);
        return authorizationFilter;
    }
}
