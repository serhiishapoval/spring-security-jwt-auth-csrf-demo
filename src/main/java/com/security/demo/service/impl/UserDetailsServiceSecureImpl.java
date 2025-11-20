package com.security.demo.service.impl;

import com.security.demo.service.UserDetailsServiceSecure;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceSecureImpl implements UserDetailsServiceSecure {

  // @PreAuthorize("hasRole('USER')")
  @Secured("ROLE_USER")
  @Override
  public String getUserDetailsMethodLevelSecurity() {
    return "User details with method level security";
  }
}
