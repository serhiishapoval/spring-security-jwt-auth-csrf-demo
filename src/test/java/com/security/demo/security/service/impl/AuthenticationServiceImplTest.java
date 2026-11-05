package com.security.demo.security.service.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.security.demo.model.http.LoginRequest;
import com.security.demo.model.http.LoginResponse;
import com.security.demo.security.JwtManagerComponent;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceImplTest {

  @Mock private AuthenticationManager authenticationManager;

  @Mock private JwtManagerComponent jwtManagerComponent;

  @InjectMocks private AuthenticationServiceImpl authenticationService;

  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void givenValidCredentials_whenAuthenticate_thenReturnsSuccessResponseWithToken() {
    // given
    final UserDetails userDetails =
        User.withUsername("user").password("password").roles("USER").build();
    final LoginRequest loginRequest = new LoginRequest();
    loginRequest.setUsername("user");
    loginRequest.setPassword("password");
    when(this.authenticationManager.authenticate(any()))
        .thenReturn(
            new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities()));
    when(this.jwtManagerComponent.generateTokenFromUsername(userDetails)).thenReturn("jwt-token");

    // when
    final LoginResponse response = this.authenticationService.authenticate(loginRequest);

    // then
    assertThat(response)
        .isEqualTo(
            LoginResponse.builder()
                .success(true)
                .message("Login successful")
                .username("user")
                .roles(List.of("ROLE_USER"))
                .jwtToken("jwt-token")
                .build());
    assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("user");
  }

  @Test
  void givenBadCredentials_whenAuthenticate_thenReturnsFailedResponseWithoutToken() {
    // given
    final LoginRequest loginRequest = new LoginRequest();
    loginRequest.setUsername("user");
    loginRequest.setPassword("wrong");
    when(this.authenticationManager.authenticate(any()))
        .thenThrow(new BadCredentialsException("bad"));

    // when
    final LoginResponse response = this.authenticationService.authenticate(loginRequest);

    // then
    assertThat(response)
        .isEqualTo(LoginResponse.builder().success(false).message("Bad credentials").build());
    verifyNoInteractions(this.jwtManagerComponent);
  }
}
