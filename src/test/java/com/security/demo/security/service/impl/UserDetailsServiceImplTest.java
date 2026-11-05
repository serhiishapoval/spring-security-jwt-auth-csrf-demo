package com.security.demo.security.service.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import com.security.demo.model.RoleEntity;
import com.security.demo.model.RoleEnum;
import com.security.demo.model.UserEntity;
import com.security.demo.repository.UserRepository;
import com.security.demo.security.model.AuthorizedUserDetails;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@ExtendWith(MockitoExtension.class)
class UserDetailsServiceImplTest {

  @Mock private UserRepository userRepository;

  @InjectMocks private UserDetailsServiceImpl userDetailsService;

  @Test
  void givenExistingUser_whenLoadUserByUsername_thenReturnsAuthorizedUserDetails() {
    // given
    when(this.userRepository.findByUsername("user"))
        .thenReturn(Optional.of(userEntity("user", RoleEnum.ROLE_USER)));

    // when
    final AuthorizedUserDetails result =
        (AuthorizedUserDetails) this.userDetailsService.loadUserByUsername("user");

    // then
    assertThat(result)
        .isEqualTo(
            AuthorizedUserDetails.builder()
                .userId(1L)
                .username("user")
                .email("user@mail.com")
                .password("encoded-password")
                .authorities(List.of(new SimpleGrantedAuthority("ROLE_USER")))
                .build());
  }

  @ParameterizedTest(name = "role {0} is exposed as its authority name")
  @EnumSource(RoleEnum.class)
  void givenUserWithRole_whenLoadUserByUsername_thenAuthorityIsRoleName(final RoleEnum role) {
    // given
    when(this.userRepository.findByUsername("user"))
        .thenReturn(Optional.of(userEntity("user", role)));

    // when
    final AuthorizedUserDetails result =
        (AuthorizedUserDetails) this.userDetailsService.loadUserByUsername("user");

    // then
    assertThat(result.getAuthorities()).isEqualTo(List.of(new SimpleGrantedAuthority(role.name())));
  }

  @Test
  void givenUnknownUser_whenLoadUserByUsername_thenThrowsUsernameNotFoundException() {
    // given
    when(this.userRepository.findByUsername("ghost")).thenReturn(Optional.empty());

    // when / then
    assertThatThrownBy(() -> this.userDetailsService.loadUserByUsername("ghost"))
        .isInstanceOf(UsernameNotFoundException.class)
        .hasMessage("User not found. Username: ghost");
  }

  private static UserEntity userEntity(final String username, final RoleEnum role) {
    return UserEntity.builder()
        .userId(1L)
        .username(username)
        .email("user@mail.com")
        .password("encoded-password")
        .role(new RoleEntity(role))
        .build();
  }
}
