package com.security.demo.security.service.impl;

import com.security.demo.model.http.LoginRequest;
import com.security.demo.model.http.LoginResponse;
import com.security.demo.security.JwtManagerComponent;
import com.security.demo.security.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

  private static final String LOGIN_SUCCESS_MESSAGE = "Login successful";
  private static final String LOGIN_FAILED_MESSAGE = "Bad credentials";

  private final JwtManagerComponent jwtManagerComponent;

  private final AuthenticationManager authenticationManager;

  @Override
  public LoginResponse authenticate(LoginRequest loginRequest) {

    Authentication authentication;
    try {
      authentication =
          this.authenticationManager.authenticate(
              new UsernamePasswordAuthenticationToken(
                  loginRequest.getUsername(), loginRequest.getPassword()));
    } catch (final AuthenticationException exception) {
      return LoginResponse.builder()
          .success(false)
          .message(LOGIN_FAILED_MESSAGE)
          .build();
    }
    
    SecurityContextHolder.getContext().setAuthentication(authentication);

    final UserDetails userDetails = (UserDetails) authentication.getPrincipal();

    return LoginResponse.builder()
        .success(true)
        .message(LOGIN_SUCCESS_MESSAGE)
        .username(userDetails.getUsername())
        .roles(userDetails.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .toList())
        .jwtToken(this.jwtManagerComponent.generateTokenFromUsername(userDetails))
        .build();
  }
}
