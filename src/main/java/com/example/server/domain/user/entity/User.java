package com.example.server.domain.user.entity;

import java.time.LocalDateTime;
import java.util.UUID;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import org.hibernate.annotations.Type;

import lombok.Getter;

@Entity
@Table(name = "user")
@Getter
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long cid;

    @Type(type = "uuid-char")
    private UUID id;

    private String username;

    private String password;

    @Type(type = "uuid-char")
    private UUID salt;

    private String roles;

    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;
}