package com.example.server.domain.social_login.service;

import org.springframework.stereotype.Service;

@Service
public class SocialLoginService {
    
    // 네이버 소셜 로그인
    public void naverLogin() {
        /*
         * 1. request body로 전달받은 인가코드를 이용해 인증토큰 발급 api 요청
         *    a  - 필수 항목 : grant_type, client_id, client_secret, code, state
         * 2. 인증토큰을 발급받은 후 네이버 프로필 조회 api 요청
         * 3. 우리 회원가입 로직 실행(user테이블에 저장 및 access token, refresh token 발급)
         *    a  - 여기서 유저마다 고유한 값을 조회해야 한다. sns 타입과 고유값을 사용해 중복 회원가입을 방지
         *    b  - 새로운 회원이라면 user entity 저장, 저장 후 우리 사이트 전용 access token, refresh token 발급
         *    c  - 이미 가입된 회원이라면 user entity 저장하지 않고, 우리 사이트 전용 access token, refresh token 발급
         * 4. 한 번 소셜로그인을 진행하면 발급된 refresh token으로 access token을 발급받을 수 있다. 소셜로그인 유저는 authorization filter를 탄다
         */

        /*
         * 생각
         * - 같은 이메일을 사용해 naver, kakao 로그인을 진행해 username이 중복된다면?
         * - username을 provider id를 저장했을 때, provier id를 가지고 api를 요청할 수 있을까?
         * - 3-a 과정을 더 일찍 실행해 1번 전에 실행할 수 있을까
         * - 소셜로그인은 user entity에 비밀번호를 저장하지 않는다
         * - 요청 dto, 응답 dto 생성하자
         * 
         * + 3-a 과정을 더 일찍 실행해~. 이 부분은 생각해보니 소셜로그인 인증절차를 생략하게 되므로 3-a 위치에서 시작하는게 맞는것같음
         */
    }

    // 카카오 소셜 로그인
    public void kakaoLogin() {

    }
}
