package br.app.pdz.api.controller;

import br.app.pdz.api.dto.JwtResponse;
import br.app.pdz.api.dto.SignInRequest;
import br.app.pdz.api.dto.SignUpRequest;
import br.app.pdz.api.service.auth.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@Slf4j
@RestController
@RequestMapping("/auth")
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
        var existenceCheck = authService.verifyExistence(signUpRequest.username(), signUpRequest.email());
        if (existenceCheck.getStatusCode() != HttpStatus.OK) return existenceCheck;

        var isUserCreated = authService.signUp(signUpRequest);
        if (isUserCreated.getStatusCode() != HttpStatus.CREATED) return isUserCreated;

        return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully!");
    }

    @GetMapping("/discord/success")
    public ResponseEntity<?> oAuth2SignIn(HttpServletRequest request, HttpServletResponse response) throws IOException {
            DefaultOAuth2User oAuth2User = (DefaultOAuth2User) request.getSession().getAttribute("user");
            request.getSession().invalidate();

            if (oAuth2User == null) {
                response.sendRedirect("/auth/discord/failure");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Discord authentication failed.");
            }

        return authService.handleOAuth2SignIn(oAuth2User);
    }

    @GetMapping("/discord/failure")
    public ResponseEntity<String> handleDiscordFailure() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Discord authentication failed.");
    }
}
