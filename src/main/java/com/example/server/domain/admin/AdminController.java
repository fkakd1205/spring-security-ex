package com.example.server.domain.admin;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.server.domain.message.Message;

@RestController
@RequestMapping("/api/admin")
public class AdminController {
    
    @GetMapping("")
    public ResponseEntity<?> hello() {
        Message message = new Message();

        try {
            message.setData("admin hello");
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
