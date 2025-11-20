package com.security.demo.secutiry.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
  private static final String STATUS_KEY = "status";

  private static final String ERROR_KEY = "error";
  private static final String ERROR_VALUE = "Unauthorized";

  private static final String MESSAGE_KEY = "message";
  private static final String PATH_KEY = "path";

  @Override
  public void commence(
      HttpServletRequest request,
      HttpServletResponse response,
      AuthenticationException authException)
      throws IOException {
    log.error("JwtAuthenticationEntryPoint. Unauthorized error.", authException);

    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

    final Map<String, Object> body = new HashMap<>();
    body.put(STATUS_KEY, HttpServletResponse.SC_UNAUTHORIZED);
    body.put(ERROR_KEY, ERROR_VALUE);
    body.put(MESSAGE_KEY, authException.getMessage());
    body.put(PATH_KEY, request.getServletPath());

    new ObjectMapper().writeValue(response.getOutputStream(), body);
  }
}
