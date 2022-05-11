package io.security.part1.domain.dto;

import lombok.Data;

@Data
public class AccountDTO {
    private Long Id;
    private String username;
    private String password;
    private String email;
    private int age;
    private String role;

}
