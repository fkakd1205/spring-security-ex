package com.example.server.security.auth;

import java.util.Optional;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.server.domain.user.dto.UserDto;
import com.example.server.domain.user.entity.User;
import com.example.server.domain.user.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> userOpt = userRepository.findByUsername(username);

        if(userOpt.isPresent()) {
            UserDto userDto = UserDto.toDto(userOpt.get());
            return new CustomUserDetails(userDto);
        }else {
            throw new UsernameNotFoundException("로그인 정보가 올바르지 않습니다.");
        }
    }
    
}
