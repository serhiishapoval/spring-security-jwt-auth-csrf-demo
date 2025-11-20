package com.security.demo.config;

import static org.springframework.security.config.Customizer.withDefaults;

import com.security.demo.model.RoleEntity;
import com.security.demo.model.RoleEnum;
import com.security.demo.model.UserEntity;
import com.security.demo.repository.RoleRepository;
import com.security.demo.repository.UserRepository;
import com.security.demo.security.filter.JwtTokenFilter;
import java.time.LocalDate;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// SpringBootWebSecurityConfiguration.java
@Configuration
@EnableWebSecurity
/*
1. prePostEnabled = true: Enables Spring Security's @PreAuthorize and @PostAuthorize annotations
 for method-level security checks before and after method execution.

2.securedEnabled = true: Enables support for the @Secured annotation,
 allowing role-based access control on methods.

3. jsr250Enabled = true: Enables support for JSR-250 annotations like @RolesAllowed,
 providing standard Java role-based security on methods.
 */
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
@RequiredArgsConstructor
public class SecurityConfiguration {

  private final JwtTokenFilter jwtTokenFilter;

  private final AuthenticationEntryPoint authenticationEntryPoint;

  @Bean
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.csrf(AbstractHttpConfigurer::disable);
    http.addFilterBefore(this.jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
    http.exceptionHandling(
        exception -> exception.authenticationEntryPoint(this.authenticationEntryPoint));
    http.authorizeHttpRequests(
        (requests) ->
            requests
                .requestMatchers("/private/**")
                .authenticated()
                .requestMatchers("/public/**")
                .permitAll()
                .requestMatchers("/login")
                .permitAll()
                /*
                .requestMatchers("/csrf-token")
                .permitAll()
                 */
                .requestMatchers("/restricted/**")
                .denyAll()
                .anyRequest()
                .authenticated());
    /*
    SessionCreationPolicy.STATELESS - Spring Security will not create or use HTTP sessions (HttpSession)
    1. No JSESSIONID cookie - Spring won't create session cookies
    2. Stateless authentication - Each request must contain complete authentication info (your JWT token)
    3. No SecurityContext persistence - Authentication details aren't stored in session memory
    4. Scalability-friendly - Perfect for microservices and load-balanced environments since no session synchronization is needed
    */
    http.sessionManagement(
        session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    http.httpBasic(withDefaults());
    return http.build();
  }

  @Bean
  public CommandLineRunner initData(
      final RoleRepository roleRepository,
      final UserRepository userRepository,
      final PasswordEncoder passwordEncoder) {
    return args -> {
      final RoleEntity userRoleEntity =
          roleRepository
              .findByRole(RoleEnum.ROLE_USER)
              .orElseGet(() -> roleRepository.save(new RoleEntity(RoleEnum.ROLE_USER)));

      final RoleEntity adminRoleEntity =
          roleRepository
              .findByRole(RoleEnum.ROLE_ADMIN)
              .orElseGet(() -> roleRepository.save(new RoleEntity(RoleEnum.ROLE_ADMIN)));

      if (!userRepository.existsByUsername("user")) {
        userRepository.save(this.getUserEntity(passwordEncoder, userRoleEntity));
      }

      if (!userRepository.existsByUsername("admin")) {
        userRepository.save(this.getAdminEntity(passwordEncoder, adminRoleEntity));
      }
    };
  }

  @Bean
  public AuthenticationManager authenticationManager(
      final AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  private UserEntity getUserEntity(
      final PasswordEncoder passwordEncoder, final RoleEntity userRoleEntity) {
    return UserEntity.builder()
        .username("user")
        .email("user@mail.com")
        .password(passwordEncoder.encode("user"))
        .accountNonLocked(false)
        .accountNonExpired(true)
        .credentialsNonExpired(true)
        .enabled(true)
        .credentialsExpiryDate(LocalDate.now().plusYears(1))
        .accountExpiryDate(LocalDate.now().plusYears(1))
        .isTwoFactorEnabled(false)
        .signUpMethod("email")
        .role(userRoleEntity)
        .build();
  }

  private UserEntity getAdminEntity(
      final PasswordEncoder passwordEncoder, final RoleEntity adminRoleEntity) {
    return UserEntity.builder()
        .username("admin")
        .email("admin@mail.com")
        .password(passwordEncoder.encode("admin"))
        .accountNonLocked(true)
        .accountNonExpired(true)
        .credentialsNonExpired(true)
        .enabled(true)
        .credentialsExpiryDate(LocalDate.now().plusYears(1))
        .accountExpiryDate(LocalDate.now().plusYears(1))
        .isTwoFactorEnabled(false)
        .signUpMethod("email")
        .role(adminRoleEntity)
        .build();
  }
}
