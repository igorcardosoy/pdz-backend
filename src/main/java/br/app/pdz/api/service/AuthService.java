package br.app.pdz.api.service;

import br.app.pdz.api.dto.JwtResponse;
import br.app.pdz.api.dto.SignInRequest;
import br.app.pdz.api.dto.SignUpRequest;
import br.app.pdz.api.model.EnumRole;
import br.app.pdz.api.model.Role;
import br.app.pdz.api.model.User;
import br.app.pdz.api.model.exeption.RoleNotFoundException;
import br.app.pdz.api.model.exeption.UserAlreadyExistsException;
import br.app.pdz.api.model.exeption.UserNotFoundException;
import br.app.pdz.api.repository.RoleRepository;
import br.app.pdz.api.repository.UserRepository;
import br.app.pdz.api.dto.UserDTO;
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

    public AuthService(JwtUtil jwtUtil, AuthenticationManager authenticationManager, UserRepository userRepository, PasswordEncoder passwordEncoder, RoleRepository roleRepository, UserService userService) {
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
        this.userService = userService;
    }

    public void verifyExistence(String username, String email) {
        if (userRepository.existsByUsername(username)) throw new UserAlreadyExistsException("Username is already in use!", HttpStatus.BAD_REQUEST);
        if (userRepository.existsByEmail(email)) throw new UserAlreadyExistsException("Email is already in use!", HttpStatus.BAD_REQUEST);
    }

    public void signUp(SignUpRequest signUpRequest) {
        verifyExistence(signUpRequest.username(), signUpRequest.email());

        String encodedPassword = passwordEncoder.encode(signUpRequest.password());

        Set<Role> roles = new HashSet<>();
        Optional<Role> userRole = roleRepository.findByName(EnumRole.ROLE_USER);

        if (userRole.isEmpty()) throw new RoleNotFoundException("Role is not found.", HttpStatus.NOT_FOUND);

        roles.add(userRole.get());

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

        user.setProfilePictureName(oAuth2User.getAttribute("avatar"));
        userRepository.save(user);

        log.info("OAuth2 user authenticated successfully: {}", user.getUsername());
        return jwtUtil.createJwtResponse(userService.loadUserByUsername(user.getUsername()));
    }

}
