package com.security.demo.security.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.util.Collection;
import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Data
@Builder
public class AuthorizedUserDetails implements UserDetails {
  private final Long userId;
  private final String username;
  private final String email;
  @JsonIgnore private final String password;
  private final Collection<? extends GrantedAuthority> authorities;
}
