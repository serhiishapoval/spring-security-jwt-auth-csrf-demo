package com.security.demo.model.http;

import java.util.List;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LoginResponse {
  private boolean success;
  private String message;
  private String jwtToken;
  private String username;
  private List<String> roles;
}
