package com.example.OAuth2.repos;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.example.OAuth2.entities.Client;

public interface ClientRepo extends JpaRepository<Client, Integer> {

    @Query("""
            SELECT c FROM Client c WHERE c.clientId = :clientId
            """)
    Optional<Client> findByClientId(String clientId);

}
