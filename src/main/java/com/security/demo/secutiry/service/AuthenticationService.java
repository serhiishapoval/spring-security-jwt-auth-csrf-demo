package com.security.demo.secutiry.service;

import com.security.demo.model.http.LoginRequest;
import com.security.demo.model.http.LoginResponse;

public interface AuthenticationService {
  LoginResponse authenticate(LoginRequest loginRequest);
}
