package com.security.demo.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CsrfController {
  /*
  Even though the CSRF token is exposed via an endpoint, only the browser can fetch it because:
  The request needs to send cookies, and browsers block cross-site cookies by default (CORS + SameSite).
  An attacker’s site can’t read the token due to same-origin policy.
  So unless the attacker is running from your frontend domain (which they can't),
   they won’t be able to access or use the CSRF token. You’re safe.
   */
  @GetMapping("/csrf-token")
  public CsrfToken csrfToken(final HttpServletRequest request) {
    return (CsrfToken) request.getAttribute(CsrfToken.class.getName());
  }
}
