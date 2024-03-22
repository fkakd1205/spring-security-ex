package com.example.server.domain.social_login.dto;

import java.util.Map;

import org.springframework.security.oauth2.client.registration.ClientRegistration;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class OAuthUserAttributes {
    private String responseId;
    private String profileName;
    private String email;
    private String profileImagePath;

    public static OAuthUserAttributes of(ClientRegistration clientRegistration, Map<String, Object> attributes) {
        String provider = clientRegistration.getRegistrationId();
        String userNameAttributeName = clientRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
        if (provider.equals("naver")) {
            return ofNaver(userNameAttributeName, attributes);
        } else if (provider.equals("kakao")) {
            return ofKakao(userNameAttributeName, attributes);
        }
        return null;
    }

    private static OAuthUserAttributes ofNaver(String userNameAttributeName, Map<String, Object> attributes) {
        Map<String, Object> response = (Map<String, Object>) attributes.get(userNameAttributeName);
        
        return new OAuthUserAttributes(
                (String) response.get("id"),
                (String) response.get("name"),
                (String) response.get("email"),
                (String) response.get("profile_image"));
    }

    private static OAuthUserAttributes ofKakao(String userNameAttributeName, Map<String, Object> attributes) {
        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get(userNameAttributeName);
        Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");

        return new OAuthUserAttributes(
                String.valueOf(attributes.get("id")),
                (String) profile.get("nickname"),
                (String) kakaoAccount.get("email"),
                (String) profile.get("profile_image_url"));
    }
}
