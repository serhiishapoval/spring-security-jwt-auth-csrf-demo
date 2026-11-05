package com.security.demo.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.security.demo.security.JwtManagerComponent;
import com.security.demo.security.service.impl.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

@ExtendWith(MockitoExtension.class)
class JwtTokenFilterTest {

  @Mock private JwtManagerComponent jwtManagerComponent;

  @Mock private UserDetailsServiceImpl userDetailsService;

  @Mock private FilterChain filterChain;

  @InjectMocks private JwtTokenFilter jwtTokenFilter;

  private final MockHttpServletRequest request = new MockHttpServletRequest();
  private final MockHttpServletResponse response = new MockHttpServletResponse();

  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void givenValidToken_whenFiltered_thenSetsAuthenticationAndContinuesChain() throws Exception {
    // given
    final UserDetails userDetails =
        User.withUsername("user").password("password").roles("USER").build();
    when(this.jwtManagerComponent.getJwtFromHeader(any())).thenReturn("token");
    when(this.jwtManagerComponent.validateJwtToken("token")).thenReturn(true);
    when(this.jwtManagerComponent.getUserNameFromJwtToken("token")).thenReturn("user");
    when(this.userDetailsService.loadUserByUsername("user")).thenReturn(userDetails);

    // when
    this.jwtTokenFilter.doFilter(this.request, this.response, this.filterChain);

    // then
    final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    assertThat(authentication.getPrincipal()).isEqualTo(userDetails);
    assertThat(List.copyOf(authentication.getAuthorities()))
        .isEqualTo(List.copyOf(userDetails.getAuthorities()));
    verify(this.filterChain).doFilter(this.request, this.response);
  }

  @Test
  void givenNoToken_whenFiltered_thenLeavesContextEmptyAndContinuesChain() throws Exception {
    // given
    when(this.jwtManagerComponent.getJwtFromHeader(any())).thenReturn(null);

    // when
    this.jwtTokenFilter.doFilter(this.request, this.response, this.filterChain);

    // then
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    verifyNoInteractions(this.userDetailsService);
    verify(this.filterChain).doFilter(this.request, this.response);
  }

  @Test
  void givenInvalidToken_whenFiltered_thenLeavesContextEmptyAndContinuesChain() throws Exception {
    // given
    when(this.jwtManagerComponent.getJwtFromHeader(any())).thenReturn("token");
    when(this.jwtManagerComponent.validateJwtToken("token")).thenReturn(false);

    // when
    this.jwtTokenFilter.doFilter(this.request, this.response, this.filterChain);

    // then
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    verify(this.jwtManagerComponent, never()).getUserNameFromJwtToken(any());
    verify(this.filterChain).doFilter(this.request, this.response);
  }

  @Test
  void givenUserLoadingFails_whenFiltered_thenExceptionIsSwallowedAndChainContinues()
      throws Exception {
    // given
    when(this.jwtManagerComponent.getJwtFromHeader(any())).thenReturn("token");
    when(this.jwtManagerComponent.validateJwtToken("token")).thenReturn(true);
    when(this.jwtManagerComponent.getUserNameFromJwtToken("token")).thenReturn("ghost");
    when(this.userDetailsService.loadUserByUsername("ghost"))
        .thenThrow(new IllegalStateException("user store unavailable"));

    // when
    this.jwtTokenFilter.doFilter(this.request, this.response, this.filterChain);

    // then
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    verify(this.filterChain).doFilter(this.request, this.response);
  }
}
