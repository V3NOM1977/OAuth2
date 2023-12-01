package com.example.OAuth2.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @GetMapping
    public String index() {
        return "Hello Wrld...!!";
    }

    @GetMapping(path = "secured")
    public String secured() {
        return "Secured...!!";
    }

}
