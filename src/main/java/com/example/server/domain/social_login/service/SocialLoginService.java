package com.example.server.domain.social_login.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.http.HttpServletResponse;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;

import com.example.server.domain.message.Message;
import com.example.server.domain.refresh_token.entity.RefreshToken;
import com.example.server.domain.refresh_token.repository.RefreshTokenRepository;
import com.example.server.domain.social_login.dto.OAuthResponse;
import com.example.server.domain.social_login.dto.OAuthUserAttributes;
import com.example.server.domain.user.dto.UserDto;
import com.example.server.domain.user.entity.User;
import com.example.server.domain.user.repository.UserRepository;
import com.example.server.security.service.JwtAuthService;
import com.fasterxml.jackson.core.exc.StreamWriteException;
import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class SocialLoginService {
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;

    // 네이버 소셜 로그인
    /*
     * 1. request body로 전달받은 인가코드를 이용해 인증토큰 발급 api 요청
     * a - 필수 항목 : grant_type, client_id, client_secret, code, state
     * 
     * 2. 인증토큰 발급 후 유저 정보 조회 api 요청
     * 
     * 3. 우리 회원가입 로직 실행 (user테이블에 저장 및 access token, refresh token 발급)
     * a - 여기서 유저마다 고유한 값이 필요하다. registrationId와 registration에서 사용되는 고유값을 사용해 중복 회원가입을 방지 -> '[registrationId]_[registration_user_id]'로 식별
     * b - 새로운 회원이라면 user entity 저장하고, 이미 가입된 회원이라면 저장된 회원을 조회한다.
     * c - 저장 후 우리 사이트 전용 access token, refresh token 발급
     * 
     * 4. 한 번 소셜로그인을 진행하면 발급된 refresh token으로 access token을 발급받을 수 있다. 소셜로그인 유저는 authorization filter를 탄다
     */
    public void socialLogin(HttpServletResponse response, String registrationId, String code) throws IOException {
        // 0. registrationId를 확인해 어떤 플랫폼에서 요청되는지 확인
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(registrationId);
    
        if (clientRegistration == null) {
            throw new IllegalArgumentException("등록되지 않은 RegistrationId");
        }

        // 1. 토큰 요청
        OAuthResponse.RequestToken tokenResponse = this.requestOAuth2AccessToken(clientRegistration, code);
        // 2. 유저 정보 조회 요청
        OAuthUserAttributes userAttributes = this.requestOAuth2UserInfo(clientRegistration, tokenResponse);
        // 3. 새로운 회원이라면 user entity 저장하고, 이미 가입된 회원이라면 저장된 회원을 조회한다.
        UserDto userDto = this.getRegisteredUser(registrationId, userAttributes);
        
        // access token, refresh token 생성
        UUID refreshTokenId = UUID.randomUUID();
        this.createAccessToken(response, userDto, refreshTokenId);
        this.createRefreshToken(userDto, refreshTokenId);
    }

    private OAuthResponse.RequestToken requestOAuth2AccessToken(ClientRegistration clientRegistration, String code) {
        String tokenRequestUri = clientRegistration.getProviderDetails().getTokenUri();

        MultiValueMap<String, String> parameter = new LinkedMultiValueMap<>();
        parameter.add("grant_type", "authorization_code");
        parameter.add("client_id", clientRegistration.getClientId());
        parameter.add("client_secret", clientRegistration.getClientSecret());
        parameter.add("code", code);
        parameter.add("state", "1234");

        OAuthResponse.RequestToken tokenResponse = WebClient.create()
                .post()
                .uri(tokenRequestUri)
                .headers(header -> {
                    header.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
                    header.setAcceptCharset(Collections.singletonList(StandardCharsets.UTF_8));
                })
                .bodyValue(parameter)
                .retrieve()
                .bodyToMono(OAuthResponse.RequestToken.class)
                .block();

        return tokenResponse;
    }

    private OAuthUserAttributes requestOAuth2UserInfo(ClientRegistration clientRegistration, OAuthResponse.RequestToken tokenResponse) {
        String userInfoRequestUri = clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri();

        OAuthUserAttributes userAttributes = OAuthUserAttributes.of(clientRegistration, WebClient.create()
                .get()
                .uri(userInfoRequestUri)
                .headers(header -> header.setBearerAuth(tokenResponse.getAccess_token()))
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .block());

        return userAttributes;
    }

    private UserDto getRegisteredUser(String registrationId, OAuthUserAttributes userAttributes) {
        String USERNAME = registrationId + "_" + userAttributes.getResponseId();
        String PASSWORD = passwordEncoder.encode(UUID.randomUUID().toString());
        
        // 3. 우리 회원가입 로직 실행(user테이블에 저장 및 access token, refresh token 발급)
        User entity = User.builder()
                .id(UUID.randomUUID())
                .username(USERNAME)
                .password(PASSWORD)
                .profileName(userAttributes.getProfileName())
                .profileImagePath(userAttributes.getProfileImagePath())
                .roles("ROLE_USER")
                .provider(registrationId)
                .providerUserId(userAttributes.getResponseId())
                .createdAt(LocalDateTime.now())
                .build();

        // 회원가입 여부 확인
        Optional<User> duplicatedUserOpt = userRepository.findByUsername(USERNAME);
        if(duplicatedUserOpt.isPresent()) {
            entity = duplicatedUserOpt.get();
        } else {
            userRepository.save(entity);
        }

        UserDto userDto = UserDto.toDto(entity);
        return userDto;
    }
    

    private void createAccessToken(HttpServletResponse response, UserDto user, UUID refreshTokenId) throws IOException {
        String accessToken = JwtAuthService.createAccessToken(user, refreshTokenId);

        // access token 발급
        ResponseCookie cookies = ResponseCookie.from("access_token", accessToken)
                .httpOnly(true)
                .domain("localhost")
                .sameSite("Strict")
                .path("/")
                .maxAge(3 * 24 * 60 * 60) // 3일
                .build();
               
        response.addHeader(HttpHeaders.SET_COOKIE, cookies.toString());
    
        Message message = new Message();
        message.setStatus(HttpStatus.OK);
        message.setMessage("success");
        message.setMemo("login_success");
        
        this.createResponseMessage(response, message);
    }

    private void createRefreshToken(UserDto user, UUID refreshTokenId) {
        // Refresh Token 저장
        String refreshToken = JwtAuthService.createRefreshToken(user);


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
            throw new RuntimeException("유효하지 않은 사용자입니다.");
        }
    }

     // response message 설정
     private void createResponseMessage(HttpServletResponse response, Message message) throws StreamWriteException, DatabindException, IOException {
        response.setContentType(MediaType.APPLICATION_JSON.toString());    
        new ObjectMapper().writeValue(response.getOutputStream(), message);
    }
}
