package com.example.OAuth2.services;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.OAuth2.entities.Client;
import com.example.OAuth2.repos.ClientRepo;

@Service
@Transactional
public class CustomClientService implements RegisteredClientRepository {

    private final ClientRepo clientRepo;

    public CustomClientService(ClientRepo clientRepo) {
        this.clientRepo = clientRepo;
    }

    @Override
    @Nullable
    public RegisteredClient findByClientId(String clientId) {
        var client = clientRepo.findByClientId(clientId)
                .orElseThrow();
        return Client.from(client);
    }

    @Override
    @Nullable
    public RegisteredClient findById(String id) {
        var client = clientRepo.findById(Integer.valueOf(id))
                .orElseThrow();
        return Client.from(client);
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        clientRepo.save(Client.from(registeredClient));
    }

}
