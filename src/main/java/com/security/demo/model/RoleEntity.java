package com.security.demo.model;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.util.HashSet;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Data
@Table(name = "roles")
public class RoleEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "role_id")
  private Integer roleId;

  @ToString.Exclude
  @Enumerated(EnumType.STRING)
  @Column(length = 20, name = "role_name")
  private RoleEnum role;

  @OneToMany(
      mappedBy = "role",
      fetch = FetchType.LAZY,
      cascade = {CascadeType.MERGE})
  @JsonBackReference
  @ToString.Exclude
  private Set<UserEntity> users = new HashSet<>();

  public RoleEntity(final RoleEnum role) {
    this.role = role;
  }
}
