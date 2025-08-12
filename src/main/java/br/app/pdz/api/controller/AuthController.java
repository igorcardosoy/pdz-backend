package br.app.pdz.api.controller;

import br.app.pdz.api.dto.*;
import br.app.pdz.api.model.Whitelist;
import br.app.pdz.api.service.AuthService;
import br.app.pdz.api.service.UserService;
import br.app.pdz.api.service.WhitelistService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/pdz-api/auth")
public class AuthController {

    private final AuthService authService;
    private final WhitelistService whitelistService;
    private final UserService userService;

    public AuthController(AuthService authService, WhitelistService whitelistService, UserService userService) {
        this.authService = authService;
        this.whitelistService = whitelistService;
        this.userService = userService;
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

    @PostMapping("/reset-password")
    public ResponseEntity<String> changePassword(@RequestBody PasswordChangeRequest passwordChangeRequest) {
        userService.changePassword(passwordChangeRequest);
        return ResponseEntity.ok("Success: Password changed successfully");
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

    @PostMapping("/whitelist/add")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> addToWhitelist(@RequestBody WhitelistRequest whitelistRequest, Principal principal) {
        try {
            whitelistService.addToWhitelist(whitelistRequest.discordUsername(), principal.getName());
            return ResponseEntity.ok("User added to whitelist successfully");
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @DeleteMapping("/whitelist/remove")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> removeFromWhitelist(@RequestBody WhitelistRequest whitelistRequest) {
        try {
            whitelistService.removeFromWhitelist(whitelistRequest.discordUsername());
            return ResponseEntity.ok("User removed from whitelist successfully");
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/whitelist")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<Whitelist>> getWhitelistedUsers() {
        return ResponseEntity.ok(whitelistService.getAllWhitelistedUsers());
    }

    @GetMapping("/administrators")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<String>> getAdmins() {
        List<String> admins = authService.getAllAdmins();
        return ResponseEntity.ok(admins);
    }

    @PostMapping("/administrators")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> addNewAdmin(@RequestBody AdmRequest admRequest) {
        try {
            authService.addNewAdmin(admRequest);
            return ResponseEntity.ok("Success: New admin added");
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/signin/discord")
    public void discordLogin(@RequestParam(required = false) String callback,
                             HttpServletResponse response) throws IOException {
        String redirectUrl = "/oauth2/authorization/discord";

        if (callback != null && !callback.isEmpty()) {
            String encodedCallback = URLEncoder.encode(callback, StandardCharsets.UTF_8);
            redirectUrl += "?state=" + encodedCallback;
        }

        response.sendRedirect(redirectUrl);
    }
}
