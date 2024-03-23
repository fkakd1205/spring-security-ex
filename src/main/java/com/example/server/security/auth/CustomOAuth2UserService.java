package com.example.server.security.auth;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.example.server.domain.social_login.dto.OAuthUserAttributes;
import com.example.server.domain.user.dto.UserDto;
import com.example.server.domain.user.entity.User;
import com.example.server.domain.user.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("#=======OAUTH USER SERVICE=======#");

        OAuth2User oAuth2User = super.loadUser(userRequest);
        ClientRegistration clientRegistration = userRequest.getClientRegistration();
        
        OAuthUserAttributes userAttributes =  OAuthUserAttributes.of(clientRegistration, oAuth2User.getAttributes());
        
        String PROVIDER = clientRegistration.getRegistrationId().toString();
        String USERNAME = PROVIDER + "_" + userAttributes.getResponseId();
        String PASSWORD = "";

        // 우리 회원가입 로직 실행(user테이블에 저장)
        User entity = User.builder()
                .id(UUID.randomUUID())
                .username(USERNAME)
                .password(PASSWORD)
                .profileName(userAttributes.getProfileName())
                .profileImagePath(userAttributes.getProfileImagePath())
                .roles("ROLE_USER")
                .provider(PROVIDER)
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
        return new CustomUserDetails(userDto);
    }
    
}
