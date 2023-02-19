package com.example.server.domain.social_login.dto;

import java.util.Map;

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

    public static OAuthUserAttributes of(String provider, Map<String, Object> attributes) {
        if (provider.equals("naver")) {
            return ofNaver(attributes);
        } else if (provider.equals("kakao")) {
            return ofKakao(attributes);
        }
        return null;
    }

    private static OAuthUserAttributes ofNaver(Map<String, Object> attributes) {
        Map<String, Object> response = (Map<String, Object>) attributes.get("response");
        
        return new OAuthUserAttributes(
                (String) response.get("id"),
                (String) response.get("name"),
                (String) response.get("email"),
                (String) response.get("profile_image"));
    }

    private static OAuthUserAttributes ofKakao(Map<String, Object> attributes) {
        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> properties = (Map<String, Object>) attributes.get("properties");

        return new OAuthUserAttributes(
                String.valueOf(attributes.get("id")),
                (String) properties.get("nickname"),
                (String) kakaoAccount.get("email"),
                (String) properties.get("profile_image"));
    }
}
