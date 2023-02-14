package com.example.server.domain.social_login.controller;

import java.net.URI;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.server.domain.message.Message;
import com.example.server.domain.social_login.service.SocialLoginService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/social-login/test")
@RequiredArgsConstructor
public class SocialLoginController {
    private final SocialLoginService socialLoginService;
    
    @PostMapping("/naver")
    public ResponseEntity<?> naverLogin() {
        Message message = new Message();

        // try {
        //     socialLoginService.naverLogin();
        //     message.setStatus(HttpStatus.OK);
        //     message.setMessage("success");
            
        // } catch (Exception e) {
        //     message.setStatus(HttpStatus.BAD_REQUEST);
        //     message.setMessage("error");
        //     message.setMemo(e.getMessage());
        // }
        // return new ResponseEntity<>(message, message.getStatus());
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create("/oauth2/authorization/naver"));
        return new ResponseEntity<>(headers, HttpStatus.MOVED_PERMANENTLY);
    }

    @PostMapping("/kakao")
    public ResponseEntity<?> kakaoLogin() {
        Message message = new Message();

        try {
            socialLoginService.kakaoLogin();
            message.setStatus(HttpStatus.OK);
            message.setMessage("success");
        } catch (Exception e) {
            message.setStatus(HttpStatus.BAD_REQUEST);
            message.setMessage("error");
            message.setMemo(e.getMessage());
        }
        return new ResponseEntity<>(message, message.getStatus());
    }
}
