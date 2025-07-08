package br.app.pdz.api.util;


import br.app.pdz.api.dto.JwtResponse;
import br.app.pdz.api.dto.UserDTO;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.stream.Collectors;

@Component
@Log4j2
public class JwtUtil {

    @Value("${pdz.api.jwtSecret}")
    private String jwtSecretStr;
    private SecretKey jwtSecret;

    @PostConstruct
    public void init() {
        jwtSecret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecretStr));
    }


    @Value("${pdz.api.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String generateJwtToken(UserDTO userDTO) {
        return Jwts.builder()
                .subject(userDTO.getUsername())
                .claim("id", userDTO.getId())
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(jwtSecret)
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith(jwtSecret)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public JwtResponse createJwtResponse(UserDTO userDTO) {
        String jwt = generateJwtToken(userDTO);

        List<String> roles = userDTO.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return new JwtResponse(
                jwt,
                userDTO.getId(),
                userDTO.getUsername(),
                roles
        );
    }

    public void validateJwtToken(String authToken) {
        Jwts.parser()
                .verifyWith(jwtSecret)
                .build()
                .parseSignedClaims(authToken);
    }

}
