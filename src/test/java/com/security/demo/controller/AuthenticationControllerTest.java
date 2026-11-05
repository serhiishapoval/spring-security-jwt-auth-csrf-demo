package com.security.demo.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.security.demo.model.http.LoginRequest;
import com.security.demo.model.http.LoginResponse;
import com.security.demo.security.service.AuthenticationService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@ExtendWith(MockitoExtension.class)
class AuthenticationControllerTest {

  @Mock private AuthenticationService authenticationService;

  @InjectMocks private AuthenticationController authenticationController;

  @Test
  void givenLoginRequest_whenAuthenticate_thenReturnsServiceResponse() {
    // given
    final LoginRequest request = new LoginRequest();
    request.setUsername("user");
    request.setPassword("password");
    final LoginResponse serviceResponse =
        LoginResponse.builder().success(true).message("Login successful").jwtToken("jwt").build();
    when(this.authenticationService.authenticate(request)).thenReturn(serviceResponse);

    // when
    final ResponseEntity<LoginResponse> response =
        this.authenticationController.authenticate(request);

    // then
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response.getBody()).isEqualTo(serviceResponse);
  }
}
