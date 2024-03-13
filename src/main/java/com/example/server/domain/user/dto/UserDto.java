package com.example.server.domain.user.dto;

import java.time.LocalDateTime;
import java.util.UUID;

import com.example.server.domain.user.entity.User;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Getter
@Builder
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class UserDto {
    private UUID id;
    private String username;
    private String password;
    private UUID salt;
    private String roles;
    private String provider;
    private String providerUserId;
    private String profileName;
    private String profileImagePath;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public static UserDto toDto(User user) {
        UserDto dto = UserDto.builder()
            .id(user.getId())
            .username(user.getUsername())
            .password(user.getPassword())
            .salt(user.getSalt())
            .roles(user.getRoles())
            .provider(user.getProvider())
            .providerUserId(user.getProviderUserId())
            .profileName(user.getProfileName())
            .profileImagePath(user.getProfileImagePath())
            .createdAt(user.getCreatedAt())
            .updatedAt(user.getUpdatedAt())
            .build();
        
            return dto;
    }
}
