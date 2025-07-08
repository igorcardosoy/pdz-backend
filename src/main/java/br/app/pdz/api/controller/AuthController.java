package br.app.pdz.api.controller;

import br.app.pdz.api.dto.JwtResponse;
import br.app.pdz.api.dto.SignInRequest;
import br.app.pdz.api.dto.SignUpRequest;
import br.app.pdz.api.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/pdz-api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signIn(@RequestBody SignInRequest signInRequest) {
        JwtResponse jwtResponse = authService.signIn(signInRequest);

        return ResponseEntity.ok(jwtResponse);
    }

    @PostMapping("/signup")
    public ResponseEntity<String> signUp(@RequestBody SignUpRequest signUpRequest) {
        authService.signUp(signUpRequest);

        return ResponseEntity.status(HttpStatus.CREATED).body("Success: User registered");
    }

    @GetMapping("/discord/success")
    public ResponseEntity<?> oAuth2SignIn(HttpServletRequest request, HttpServletResponse response) {
        DefaultOAuth2User oAuth2User = (DefaultOAuth2User) request.getSession().getAttribute("user");

        JwtResponse jwtResponse = authService.handleOAuth2SignIn(oAuth2User, request, response);

        return ResponseEntity.ok(jwtResponse);
    }

    @GetMapping("/discord/failure")
    public ResponseEntity<String> handleDiscordFailure() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Error: Discord authentication failed.");
    }
}
