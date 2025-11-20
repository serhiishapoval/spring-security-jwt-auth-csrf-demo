package com.security.demo.model.http;

import lombok.Data;

@Data
public class LoginRequest {
  private String username;
  private String password;
}
