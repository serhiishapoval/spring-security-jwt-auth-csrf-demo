package com.security.demo.model;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.LocalDate;
import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Table(
    name = "users",
    uniqueConstraints = {
      @UniqueConstraint(columnNames = "username"),
      @UniqueConstraint(columnNames = "email")
    })
@Builder
public class UserEntity {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "user_id")
  private Long userId;

  @NotBlank
  @Size(max = 20)
  @Column(name = "username")
  private String username;

  @NotBlank
  @Size(max = 50)
  @Email
  @Column(name = "email")
  private String email;

  @Size(max = 120)
  @Column(name = "password")
  @JsonIgnore
  private String password;

  private boolean accountNonLocked = true;
  private boolean accountNonExpired = true;
  private boolean credentialsNonExpired = true;
  private boolean enabled = true;

  private LocalDate credentialsExpiryDate;
  private LocalDate accountExpiryDate;

  private String twoFactorSecret;
  private boolean isTwoFactorEnabled = false;
  private String signUpMethod;

  @ManyToOne(
      fetch = FetchType.EAGER,
      cascade = {CascadeType.MERGE})
  @JoinColumn(name = "role_id", referencedColumnName = "role_id")
  @JsonBackReference
  @ToString.Exclude
  private RoleEntity role;

  @CreationTimestamp
  @Column(updatable = false)
  private LocalDateTime createdDate;

  @UpdateTimestamp private LocalDateTime updatedDate;
}
