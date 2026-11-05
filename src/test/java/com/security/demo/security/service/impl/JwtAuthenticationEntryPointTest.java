package com.security.demo.security.service.impl;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;

class JwtAuthenticationEntryPointTest {

  private final JwtAuthenticationEntryPoint entryPoint = new JwtAuthenticationEntryPoint();

  @Test
  void givenUnauthenticatedRequest_whenCommence_thenWritesUnauthorizedJsonBody() throws Exception {
    // given
    final MockHttpServletRequest request = new MockHttpServletRequest();
    request.setServletPath("/private/data");
    final MockHttpServletResponse response = new MockHttpServletResponse();

    // when
    this.entryPoint.commence(
        request, response, new BadCredentialsException("Full authentication is required"));

    // then
    assertThat(response.getStatus()).isEqualTo(401);
    assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
    final Map<String, Object> body =
        new ObjectMapper()
            .readValue(response.getContentAsString(), new TypeReference<Map<String, Object>>() {});
    assertThat(body)
        .isEqualTo(
            Map.of(
                "status", 401,
                "error", "Unauthorized",
                "message", "Full authentication is required",
                "path", "/private/data"));
  }
}
