package br.app.pdz.api.service;

import br.app.pdz.api.model.User;
import br.app.pdz.api.repository.UserRepository;
import br.app.pdz.api.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

@Component
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;

    public OAuth2LoginSuccessHandler(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        Map<String, Object> attributes = token.getPrincipal().getAttributes();

        String discordId = (String) attributes.get("id");
        String username = (String) attributes.get("username");
        String email = (String) attributes.get("email");

        Optional<User> optionalUser = userRepository.findByDiscordId(discordId);

        if (optionalUser.isEmpty()) {
            User user = new User();
            user.setDiscordId(discordId);
            user.setUsername(username);
            user.setEmail(email);

            userRepository.save(user);
        }

        JwtUtil jwtUtil = new JwtUtil();
        String responseToken = jwtUtil.generateJwtToken(authentication);
        response.setHeader("Authorization", "Bearer " + responseToken);
    }
}
