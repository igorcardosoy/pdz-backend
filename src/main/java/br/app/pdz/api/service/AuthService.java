package br.app.pdz.api.service;

import br.app.pdz.api.dto.*;
import br.app.pdz.api.model.EnumRole;
import br.app.pdz.api.model.Role;
import br.app.pdz.api.model.User;
import br.app.pdz.api.exception.RoleNotFoundException;
import br.app.pdz.api.exception.UserAlreadyExistsException;
import br.app.pdz.api.exception.UserNotFoundException;
import br.app.pdz.api.exception.UserNotInWhiteList;
import br.app.pdz.api.repository.RoleRepository;
import br.app.pdz.api.repository.UserRepository;
import br.app.pdz.api.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
@Log4j2
public class AuthService {

    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final UserService userService;
    private final WhitelistService whitelistService;

    public AuthService(JwtUtil jwtUtil, AuthenticationManager authenticationManager, UserRepository userRepository, PasswordEncoder passwordEncoder, RoleRepository roleRepository, UserService userService, WhitelistService whitelistService) {
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
        this.userService = userService;
        this.whitelistService = whitelistService;
    }

    public void verifyExistence(String username, String email) {
        if (userRepository.existsByUsername(username))
            throw new UserAlreadyExistsException("Username is already in use!", HttpStatus.BAD_REQUEST);
        if (userRepository.existsByEmail(email))
            throw new UserAlreadyExistsException("Email is already in use!", HttpStatus.BAD_REQUEST);
    }

    public void signUp(SignUpRequest signUpRequest) {
        verifyExistence(signUpRequest.username(), signUpRequest.email());

        String encodedPassword = passwordEncoder.encode(signUpRequest.password());

        Set<Role> roles = new HashSet<>();
        Optional<Role> userRole = roleRepository.findByName(EnumRole.ROLE_USER);

        if (userRole.isEmpty()) throw new RoleNotFoundException("Role is not found.", HttpStatus.NOT_FOUND);

        roles.add(userRole.get());

        if (userRepository.findAll().isEmpty()) {
            Optional<Role>  adminRole = roleRepository.findByName(EnumRole.ROLE_ADMIN);
            if (adminRole.isEmpty()) throw new RoleNotFoundException("Role is not found.", HttpStatus.NOT_FOUND);

            roles.add(adminRole.get());
        }

        User user = new User();
        user.setUsername(signUpRequest.username());
        user.setEmail(signUpRequest.email());
        user.setPassword(encodedPassword);
        user.setRoles(roles);
        userRepository.save(user);

        log.info("User registered successfully: {}", user.getUsername());
    }

    public JwtResponse signIn(SignInRequest signInRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        signInRequest.username(),
                        signInRequest.password()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        log.info("User authenticated successfully: {}", signInRequest.username());
        return jwtUtil.createJwtResponse((UserDTO) authentication.getPrincipal());
    }

    public JwtResponse handleOAuth2SignIn(DefaultOAuth2User oAuth2User, HttpServletRequest request, HttpServletResponse response) {
        if (oAuth2User == null) {
            try {
                response.sendRedirect("/auth/discord/failure");
            } catch (IOException e) {
                throw new UserNotFoundException("OAuth2 user is null", HttpStatus.BAD_REQUEST);
            }
            throw new UserNotFoundException("OAuth2 user is null", HttpStatus.BAD_REQUEST);
        }

        request.getSession().invalidate();

        User user = userRepository.findByDiscordId(oAuth2User.getAttribute("id"))
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setDiscordId(oAuth2User.getAttribute("id"));
                    newUser.setUsername(oAuth2User.getAttribute("username"));
                    newUser.setEmail(oAuth2User.getAttribute("email"));

                    Set<Role> roles = new HashSet<>();
                    roles.add(roleRepository.findByName(EnumRole.ROLE_USER).orElse(null));
                    newUser.setRoles(roles);

                    return newUser;
                });

        if (whitelistService.isUserWhitelisted(user.getUsername())) {
            log.info("OAuth2 user is whitelisted: {}", user.getUsername());
        } else {
            log.warn("OAuth2 user is not whitelisted: {}", user.getUsername());
            throw new UserNotInWhiteList("User is not whitelisted", HttpStatus.UNAUTHORIZED);
        }

        user.setProfilePictureName(oAuth2User.getAttribute("avatar"));
        userRepository.save(user);

        log.info("OAuth2 user authenticated successfully: {}", user.getUsername());
        return jwtUtil.createJwtResponse(userService.loadUserByUsername(user.getUsername()));
    }

    public void addNewAdmin(AdmRequest admRequest) {
        String username = admRequest.username();
        String email = admRequest.email();

        if (!userRepository.existsByUsernameAndEmail(username, email)) {
            throw new UserNotFoundException("User not found with provided username and email", HttpStatus.NOT_FOUND);
        }

        User user = userRepository.findByUsernameAndEmail(username, email)
                .orElseThrow(() -> new UserNotFoundException("User not found with provided username and email", HttpStatus.NOT_FOUND));

        Role adminRole = roleRepository.findByName(EnumRole.ROLE_ADMIN)
                .orElseThrow(() -> new RoleNotFoundException("Admin role not found", HttpStatus.NOT_FOUND));

        if (user.getRoles().stream().anyMatch(role -> role.getName() == EnumRole.ROLE_ADMIN)) {
            throw new IllegalArgumentException("User already has admin privileges");
        }

        user.getRoles().add(adminRole);
        userRepository.save(user);

        log.info("User {} has been granted admin privileges", username);

    }

    public List<String> getAllAdmins() {
        List<User> admins = userRepository.findAll().stream()
                .filter(user -> user.getRoles().stream().anyMatch(role -> role.getName() == EnumRole.ROLE_ADMIN))
                .toList();

        if (admins.isEmpty()) {
            return List.of();
        }

        log.info("Retrieved list of admins: {}", admins);
        return admins.stream().map(User::getUsername).toList();
    }

}
