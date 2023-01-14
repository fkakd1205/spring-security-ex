package com.example.server.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import com.example.server.security.auth.CustomUserDetailsService;
import com.example.server.security.auth.JwtAuthenticationFilter;
import com.example.server.security.auth.JwtAuthenticationProvider;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final CustomUserDetailsService customUserDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        AuthenticationManager authenticationManager = authenticationManager(http.getSharedObject(AuthenticationConfiguration.class));
        JwtAuthenticationFilter jwtAuthenticationFilter = jwtAuthenticationFilter(authenticationManager);

        http
            .cors().disable()
            .csrf().disable();
            // .formLogin().disable();
        
        http
            .headers().frameOptions().sameOrigin();

        http
            .formLogin()
            .usernameParameter("uesrname")      // form login에서 왜 uesrname으로 넘어올까..
            .permitAll()
            .loginProcessingUrl("/api/v1/login")
            .defaultSuccessUrl("/");

        http
            .authorizeRequests(request -> request
                .antMatchers(
                    "/api/v1/home",
                    "/api/v1/login",
                    "/api/v1/signup"
                ).permitAll()
                .anyRequest().authenticated()
            );

        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

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
        JwtAuthenticationFilter authenticationFilter = new JwtAuthenticationFilter();
        authenticationFilter.setAuthenticationManager(authenticationManager);

        SecurityContextRepository contextRepository = new HttpSessionSecurityContextRepository();
        authenticationFilter.setSecurityContextRepository(contextRepository);

        return authenticationFilter;
    }
}
