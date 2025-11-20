package com.security.demo.controller;

import com.security.demo.model.http.LoginRequest;
import com.security.demo.model.http.LoginResponse;
import com.security.demo.security.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthenticationController {

  private final AuthenticationService authenticationService;

  @PostMapping("/login")
  public ResponseEntity<LoginResponse> authenticate(@RequestBody final LoginRequest loginRequest) {
    return ResponseEntity.ok(this.authenticationService.authenticate(loginRequest));
  }
}
