package com.shiva.auth_server.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @GetMapping("/api/secure-data")
    public String home(Authentication auth) {
        return "Access granted to: " + auth.getName();
    }
}
