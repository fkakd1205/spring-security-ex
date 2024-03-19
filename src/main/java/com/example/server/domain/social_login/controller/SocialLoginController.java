// package com.example.server.domain.social_login.controller;

// import javax.servlet.http.HttpServletResponse;

// import org.springframework.http.HttpStatus;
// import org.springframework.http.ResponseEntity;
// import org.springframework.web.bind.annotation.PathVariable;
// import org.springframework.web.bind.annotation.PostMapping;
// import org.springframework.web.bind.annotation.RequestMapping;
// import org.springframework.web.bind.annotation.RequestParam;
// import org.springframework.web.bind.annotation.RestController;

// import com.example.server.domain.message.Message;
// import com.example.server.domain.social_login.service.SocialLoginService;

// import lombok.RequiredArgsConstructor;

// @RestController
// @RequestMapping("/api/social-login")
// @RequiredArgsConstructor
// public class SocialLoginController {
//     private final SocialLoginService socialLoginService;
    
//     @PostMapping("/{provider}")
//     public ResponseEntity<?> socialLogin(HttpServletResponse response, @PathVariable(name = "provider") String provider, @RequestParam String code) {
//         Message message = new Message();

//         try {
//             // socialLoginService.socialLogin(response, provider, code);
//             System.out.println("hihihihi social login!!!");
//             message.setStatus(HttpStatus.OK);
//             message.setMessage("success");
            
//         } catch (Exception e) {
//             message.setStatus(HttpStatus.BAD_REQUEST);
//             message.setMessage("error");
//             message.setMemo(e.getMessage());
//         }
//         return new ResponseEntity<>(message, message.getStatus());
//     }
// }
