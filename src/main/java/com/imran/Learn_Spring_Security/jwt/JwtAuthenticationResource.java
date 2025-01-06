package com.imran.Learn_Spring_Security.jwt;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import java.time.Instant;

@RestController
public class JwtAuthenticationResource {
    private final JwtEncoder jwtEncoder;

    public JwtAuthenticationResource(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    @PostMapping("/authenticate")
    public JwtResponse authenticate() {
        // Retrieve the current authentication object from Spring Security
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String token = createToken(authentication);
        return new JwtResponse(token);
    }

    private String createToken(Authentication authentication) {
        // Build JWT claims
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(900)) // 15 minutes expiry
                .subject(authentication.getName())
                .claim("scope", createScope(authentication))
                .build();

        // Encode the claims into a JWT token
        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    private String createScope(Authentication authentication) {
        // Create a space-separated list of authorities/roles
        return String.join(" ", authentication.getAuthorities().stream()
                .map(grantedAuthority -> grantedAuthority.getAuthority())
                .toList());
    }
}

record JwtResponse(String token) {
}
