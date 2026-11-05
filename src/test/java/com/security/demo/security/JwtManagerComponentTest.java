package com.security.demo.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.jsonwebtoken.security.SignatureException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

class JwtManagerComponentTest {

  private static final int ONE_HOUR_MS = 3_600_000;

  // 32 bytes, the minimum key size for HMAC-SHA256
  private static final String SECRET = base64("0123456789abcdef0123456789abcdef");
  private static final String OTHER_SECRET = base64("fedcba9876543210fedcba9876543210");

  private JwtManagerComponent jwtManagerComponent;

  @BeforeEach
  void setUp() {
    this.jwtManagerComponent = jwtManager(SECRET, ONE_HOUR_MS);
  }

  private static String base64(final String value) {
    return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }

  private static JwtManagerComponent jwtManager(final String secret, final int expirationMs) {
    final JwtManagerComponent component = new JwtManagerComponent();
    ReflectionTestUtils.setField(component, "jwtSecret", secret);
    ReflectionTestUtils.setField(component, "jwtExpirationMs", expirationMs);
    return component;
  }

  private static UserDetails user() {
    return User.withUsername("user").password("password").roles("USER").build();
  }

  @ParameterizedTest(name = "header [{0}] yields token [{1}]")
  @CsvSource({"'Bearer abc.def.ghi', abc.def.ghi", "'Bearer    token  ', token", "'Basic abc', ''"})
  void givenAuthorizationHeader_whenGetJwtFromHeader_thenReturnsBearerTokenOrNull(
      final String header, final String expectedToken) {
    // given
    final MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("Authorization", header);

    // when
    final String token = this.jwtManagerComponent.getJwtFromHeader(request);

    // then
    assertThat(token).isEqualTo(expectedToken.isEmpty() ? null : expectedToken);
  }

  @Test
  void givenNoAuthorizationHeader_whenGetJwtFromHeader_thenReturnsNull() {
    // given
    final MockHttpServletRequest request = new MockHttpServletRequest();

    // when
    final String token = this.jwtManagerComponent.getJwtFromHeader(request);

    // then
    assertThat(token).isNull();
  }

  @Test
  void givenUserDetails_whenGenerateTokenAndReadUsername_thenReturnsSameUsername() {
    // given
    final String token = this.jwtManagerComponent.generateTokenFromUsername(user());

    // when
    final String username = this.jwtManagerComponent.getUserNameFromJwtToken(token);

    // then
    assertThat(username).isEqualTo("user");
    assertThat(this.jwtManagerComponent.validateJwtToken(token)).isTrue();
  }

  @ParameterizedTest(name = "invalid token [{0}] is rejected")
  @NullAndEmptySource
  @ValueSource(strings = {"not-a-jwt"})
  void givenInvalidToken_whenValidateJwtToken_thenReturnsFalse(final String token) {
    // given

    // when
    final boolean valid = this.jwtManagerComponent.validateJwtToken(token);

    // then
    assertThat(valid).isFalse();
  }

  @Test
  void givenExpiredToken_whenValidateJwtToken_thenReturnsFalse() {
    // given
    final JwtManagerComponent expiredTokenIssuer = jwtManager(SECRET, -ONE_HOUR_MS);
    final String expiredToken = expiredTokenIssuer.generateTokenFromUsername(user());

    // when
    final boolean valid = this.jwtManagerComponent.validateJwtToken(expiredToken);

    // then
    assertThat(valid).isFalse();
  }

  @Test
  void givenTokenSignedWithOtherKey_whenValidateJwtToken_thenSignatureExceptionPropagates() {
    // given
    final JwtManagerComponent otherKeyIssuer = jwtManager(OTHER_SECRET, ONE_HOUR_MS);
    final String foreignToken = otherKeyIssuer.generateTokenFromUsername(user());

    // when / then
    // Current behaviour: SignatureException is not in the caught list, so it escapes.
    assertThatThrownBy(() -> this.jwtManagerComponent.validateJwtToken(foreignToken))
        .isInstanceOf(SignatureException.class);
  }
}
