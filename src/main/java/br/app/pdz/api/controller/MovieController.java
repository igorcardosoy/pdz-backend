package br.app.pdz.api.controller;

import br.app.pdz.api.dto.JackettSearchResponse;
import br.app.pdz.api.service.JackettService;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@Log4j2
@RequestMapping("/pdz-api/movies")
@PreAuthorize("hasAnyRole('USER', 'MODERATOR', 'ADMIN')")
public class MovieController {

    private final JackettService jackettService;

    public MovieController(JackettService jackettService) {
        this.jackettService = jackettService;
    }

    @GetMapping("/search")
    public ResponseEntity<JackettSearchResponse> searchMovies(
            @RequestParam("query") String query,
            @RequestParam(value = "limit", defaultValue = "10") int limit) {

        log.info("Searching for movies with query: {} and limit: {}", query, limit);

        if (query == null || query.trim().isEmpty()) {
            return ResponseEntity.badRequest().build();
        }

        if (limit <= 0 || limit > 100) {
            limit = 10;
        }

        JackettSearchResponse response = jackettService.searchMovies(query, limit);

        return ResponseEntity.ok(response);
    }
}

