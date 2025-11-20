package com.security.demo.security.service.impl;

import com.security.demo.model.UserEntity;
import com.security.demo.repository.UserRepository;
import com.security.demo.security.model.AuthorizedUserDetails;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
  private static final String USER_NOT_FOUND_ERROR_MESSAGE = "User not found. Username: ";

  private final UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
    final UserEntity userEntity =
        this.userRepository
            .findByUsername(username)
            .orElseThrow(
                () -> new UsernameNotFoundException(USER_NOT_FOUND_ERROR_MESSAGE + username));

    return AuthorizedUserDetails.builder()
        .userId(userEntity.getUserId())
        .username(userEntity.getUsername())
        .email(userEntity.getEmail())
        .password(userEntity.getPassword())
        .authorities(List.of(new SimpleGrantedAuthority(userEntity.getRole().getRole().name())))
        .build();
  }
}
