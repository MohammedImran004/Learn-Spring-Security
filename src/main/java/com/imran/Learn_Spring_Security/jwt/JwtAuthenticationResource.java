package com.imran.Learn_Spring_Security.jwt;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.context.SecurityContextHolder;

@RestController
public class JwtAuthenticationResource {

    @PostMapping("/authenticate")
    public Authentication authenticate() {
        // Retrieve the current authentication object from Spring Security
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication;
    }
}
