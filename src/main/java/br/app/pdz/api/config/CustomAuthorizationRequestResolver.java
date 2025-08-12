package br.app.pdz.api.config;

import br.app.pdz.api.service.CallbackService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private final DefaultOAuth2AuthorizationRequestResolver defaultResolver;
    private final CallbackService callbackService;

    public CustomAuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository, CallbackService callbackService) {
        this.defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");
        this.callbackService = callbackService;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        OAuth2AuthorizationRequest authorizationRequest = defaultResolver.resolve(request);

        if (authorizationRequest != null) {
            return customizeAuthorizationRequest(authorizationRequest, request);
        }

        return authorizationRequest;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        OAuth2AuthorizationRequest authorizationRequest = defaultResolver.resolve(request, clientRegistrationId);

        if (authorizationRequest != null && "discord".equals(clientRegistrationId)) {
            return customizeAuthorizationRequest(authorizationRequest, request);
        }

        return authorizationRequest;
    }

    private OAuth2AuthorizationRequest customizeAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request) {
        String customState = request.getParameter("state");

        if (customState != null && !customState.isEmpty()) {
            log.info("Personalizando authorization request com state customizado: {}", customState);

            // Armazena o state original gerado pelo Spring Security associado ao nosso state customizado
            String originalState = authorizationRequest.getState();
            callbackService.storeStateMapping(originalState, customState);

            log.info("Mapeamento criado: {} -> {}", originalState, customState);

            return OAuth2AuthorizationRequest.from(authorizationRequest)
                    .state(originalState) // Mantém o state original do Spring Security
                    .build();
        }

        return authorizationRequest;
    }
}
