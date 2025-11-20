package com.security.demo.security.filter;

import static java.util.Objects.nonNull;

import com.security.demo.security.JwtManagerComponent;
import com.security.demo.security.service.impl.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {

  private final JwtManagerComponent jwtManagerComponent;
  private final UserDetailsServiceImpl userDetailsService;

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    log.debug("doFilterInternal. JwtTokenFilter called for URI: {}", request.getRequestURI());
    try {
      final String jwt = this.jwtManagerComponent.getJwtFromHeader(request);

      if (nonNull(jwt) && this.jwtManagerComponent.validateJwtToken(jwt)) {
        String username = this.jwtManagerComponent.getUserNameFromJwtToken(jwt);

        final UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

        final UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
            new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        log.info(
            "doFilterInternal. usernamePasswordAuthenticationToken: {}",
            usernamePasswordAuthenticationToken);

        usernamePasswordAuthenticationToken.setDetails(
            new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
      }
    } catch (final Exception e) {
      log.error("doFilterInternal. Error during JwtTokenFilter execution. ", e);
    }

    filterChain.doFilter(request, response);
  }
}
