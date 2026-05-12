package br.app.pdz.api.controller;

import br.app.pdz.api.dto.MovieDTO;
import br.app.pdz.api.dto.MovieHistoryDTO;
import br.app.pdz.api.service.MovieHistoryService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/pdz-api/history")
@PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
public class MovieHistoryController {

    private final MovieHistoryService movieHistoryService;

    public MovieHistoryController(MovieHistoryService movieHistoryService) {
        this.movieHistoryService = movieHistoryService;
    }

    @GetMapping
    public ResponseEntity<List<MovieHistoryDTO>> getHistory() {
        return ResponseEntity.ok(movieHistoryService.getHistory());
    }

    @PostMapping
    public ResponseEntity<MovieHistoryDTO> addToHistory(@RequestBody MovieDTO movieDTO) {
        MovieHistoryDTO created = movieHistoryService.addToHistory(movieDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> removeFromHistory(@PathVariable Long id) {
        movieHistoryService.removeFromHistory(id);
        return ResponseEntity.noContent().build();
    }
}

