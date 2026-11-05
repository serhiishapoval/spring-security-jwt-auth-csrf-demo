package com.security.demo.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.security.demo.model.RoleEntity;
import com.security.demo.model.RoleEnum;
import com.security.demo.model.UserEntity;
import com.security.demo.repository.RoleRepository;
import com.security.demo.repository.UserRepository;
import com.security.demo.security.filter.JwtTokenFilter;
import com.security.demo.security.service.impl.JwtAuthenticationEntryPoint;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class SecurityConfigurationInitDataTest {

  @Mock private JwtTokenFilter jwtTokenFilter;

  @Mock private JwtAuthenticationEntryPoint authenticationEntryPoint;

  @Mock private RoleRepository roleRepository;

  @Mock private UserRepository userRepository;

  @Mock private PasswordEncoder passwordEncoder;

  private CommandLineRunner initData;

  @BeforeEach
  void setUp() {
    this.initData =
        new SecurityConfiguration(this.jwtTokenFilter, this.authenticationEntryPoint)
            .initData(this.roleRepository, this.userRepository, this.passwordEncoder);
  }

  @Test
  void givenEmptyDatabase_whenInitData_thenCreatesRolesAndDemoUsers() throws Exception {
    // given
    when(this.roleRepository.findByRole(any())).thenReturn(Optional.empty());
    when(this.roleRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
    when(this.userRepository.existsByUsername(anyString())).thenReturn(false);
    when(this.passwordEncoder.encode("user")).thenReturn("encoded-user");
    when(this.passwordEncoder.encode("admin")).thenReturn("encoded-admin");
    final ArgumentCaptor<UserEntity> captor = ArgumentCaptor.forClass(UserEntity.class);

    // when
    this.initData.run();

    // then
    verify(this.roleRepository).save(new RoleEntity(RoleEnum.ROLE_USER));
    verify(this.roleRepository).save(new RoleEntity(RoleEnum.ROLE_ADMIN));
    verify(this.userRepository, times(2)).save(captor.capture());
    assertThat(captor.getAllValues())
        .usingRecursiveComparison()
        .ignoringFieldsMatchingRegexes(".*Date")
        .isEqualTo(
            List.of(
                UserEntity.builder()
                    .username("user")
                    .email("user@mail.com")
                    .password("encoded-user")
                    .accountNonLocked(false)
                    .accountNonExpired(true)
                    .credentialsNonExpired(true)
                    .enabled(true)
                    .isTwoFactorEnabled(false)
                    .signUpMethod("email")
                    .role(new RoleEntity(RoleEnum.ROLE_USER))
                    .build(),
                UserEntity.builder()
                    .username("admin")
                    .email("admin@mail.com")
                    .password("encoded-admin")
                    .accountNonLocked(true)
                    .accountNonExpired(true)
                    .credentialsNonExpired(true)
                    .enabled(true)
                    .isTwoFactorEnabled(false)
                    .signUpMethod("email")
                    .role(new RoleEntity(RoleEnum.ROLE_ADMIN))
                    .build()));
  }

  @Test
  void givenExistingRolesAndUsers_whenInitData_thenNothingIsSaved() throws Exception {
    // given
    when(this.roleRepository.findByRole(RoleEnum.ROLE_USER))
        .thenReturn(Optional.of(new RoleEntity(RoleEnum.ROLE_USER)));
    when(this.roleRepository.findByRole(RoleEnum.ROLE_ADMIN))
        .thenReturn(Optional.of(new RoleEntity(RoleEnum.ROLE_ADMIN)));
    when(this.userRepository.existsByUsername(eq("user"))).thenReturn(true);
    when(this.userRepository.existsByUsername(eq("admin"))).thenReturn(true);

    // when
    this.initData.run();

    // then
    verify(this.roleRepository, never()).save(any());
    verify(this.userRepository, never()).save(any());
  }
}
