package com.example.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.example.server.config.auth.JwtAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors().disable()
            .csrf().disable()
            .formLogin().disable();
        
        http
            .headers().frameOptions().sameOrigin();

        http
            .authorizeRequests(request -> request
                .antMatchers(
                    "/api/v1/home",
                    "/api/v1/login",
                    "/api/v1/signup"
                ).permitAll()
                .anyRequest().authenticated()
            );

        // TODO :: authentication manager 생성
        http.addFilterBefore(new JwtAuthenticationFilter(new AntPathRequestMatcher("/api/v1/login")), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
    
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
