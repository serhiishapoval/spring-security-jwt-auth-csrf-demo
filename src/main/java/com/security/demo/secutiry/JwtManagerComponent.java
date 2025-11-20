package com.security.demo.secutiry;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.Date;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class JwtManagerComponent {
  private static final String AUTHORIZATION_HEADER = "Authorization";
  private static final String BEARER_PREFIX = "Bearer ";

  @Value("${spring.app.jwt.secret}")
  private String jwtSecret;

  @Value("${spring.app.jwt.expiration-ms}")
  private int jwtExpirationMs;

  public String getJwtFromHeader(final HttpServletRequest request) {
    final String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
    log.info("getJwtFromHeader. Authorization Header: {}", bearerToken);
    if (bearerToken != null && bearerToken.startsWith(BEARER_PREFIX)) {
      return bearerToken.substring(BEARER_PREFIX.length()).trim();
    }
    return null;
  }

  public String generateTokenFromUsername(final UserDetails userDetails) {
    return Jwts.builder()
        .subject(userDetails.getUsername())
        .issuedAt(new Date())
        .expiration(new Date((new Date()).getTime() + this.jwtExpirationMs))
        .signWith(this.getKey())
        .compact();
  }

  public String getUserNameFromJwtToken(final String token) {
    return Jwts.parser()
        .verifyWith((SecretKey) this.getKey())
        .build()
        .parseSignedClaims(token)
        .getPayload()
        .getSubject();
  }

  public boolean validateJwtToken(String authToken) {
    try {
      System.out.println("Validate");
      Jwts.parser().verifyWith((SecretKey) this.getKey()).build().parseSignedClaims(authToken);
      return true;
    } catch (MalformedJwtException e) {
      log.error("validateJwtToken. Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      log.error("validateJwtToken. JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      log.error("validateJwtToken. JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      log.error("validateJwtToken. JWT claims string is empty: {}", e.getMessage());
    }
    return false;
  }

  private Key getKey() {
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(this.jwtSecret));
  }
}
