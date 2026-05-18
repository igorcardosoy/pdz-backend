package br.app.pdz.api.filter;

import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Debug filter para logar Authorization headers e requisições
 */
@Component
@Log4j2
public class JwtDebugFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String authorization = request.getHeader("Authorization");
        String path = request.getRequestURI();
        String method = request.getMethod();

        if (path.startsWith("/pdz-api/")) {
            String bearer = authorization != null ? authorization.substring(0, Math.min(50, authorization.length())) : "NO_HEADER";
            log.debug("[JWT Debug] {} {} | Authorization: {}", method, path, bearer);
        }

        filterChain.doFilter(request, response);
    }
}

