package com.security.demo.controller;

import com.security.demo.service.UserDetailsServiceSecure;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class SpringSecurityTestController {

  private final UserDetailsServiceSecure userDetailsServiceSecure;

  // No one can access this endpoint
  @GetMapping("/restricted/information")
  public String restrictedInformation() {
    return "Restricted information endpoint";
  }

  /*
  Only users with the 'USER' role can access these endpoints
   */
  @PreAuthorize("hasRole('USER')")
  @GetMapping("/user/details")
  public String getUserDetails() {
    return "User details endpoint";
  }

  //If you are using CSRF protection, ensure that your PUT request includes X-XSRF-TOKEN as a header
  @PreAuthorize("hasRole('USER')")
  @PutMapping("/user/details")
  public String updateUserDetails() {
    return "Update User details endpoint";
  }

  @GetMapping("/user/details/method")
  public String getUserDetailsMethodLevelSecurity() {
    return this.userDetailsServiceSecure.getUserDetailsMethodLevelSecurity();
  }

  /*
  Only users with the 'ADMIN' role can access these endpoints
   */
  @PreAuthorize("hasRole('ADMIN')")
  @GetMapping("/admin/details")
  public String getAdminDetails() {
    return "Admin details endpoint";
  }

  @PreAuthorize("hasRole('ADMIN')")
  @PutMapping("/admin/details")
  public String updateAdminDetails() {
    return "Update Admin details endpoint";
  }

  /*
  Users with either 'USER' or 'ADMIN' roles can access these endpoints
   */
  @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
  // @PreAuthorize("hasAnyAuthority('ROLE_USER','ROLE_ADMIN')")
  @GetMapping("/user-admin/details")
  public String getUserAndAdminDetails(@AuthenticationPrincipal final UserDetails userDetails) {
    return "User-Admin details endpoint. Current User: " + userDetails.getUsername();
  }

  /*
  Paths under /private/** require authentication
   */
  @GetMapping("/private/information")
  public String privateInformation() {
    return "Private information endpoint";
  }

  /*
  Paths under /public/** are accessible to everyone
   */
  @GetMapping("/public/information")
  public String publicInformation() {
    return "Public information endpoint";
  }
}
