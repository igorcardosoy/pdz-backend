package br.app.pdz.api.service;

import br.app.pdz.api.dto.MovieDTO;
import br.app.pdz.api.dto.MovieHistoryDTO;
import br.app.pdz.api.dto.UserDTO;
import br.app.pdz.api.exception.UserNotFoundException;
import br.app.pdz.api.model.MovieHistory;
import br.app.pdz.api.model.User;
import br.app.pdz.api.repository.MovieHistoryRepository;
import br.app.pdz.api.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
public class MovieHistoryService {

    private final MovieHistoryRepository movieHistoryRepository;
    private final UserRepository userRepository;
    private final UserService userService;

    public MovieHistoryService(MovieHistoryRepository movieHistoryRepository, UserRepository userRepository, UserService userService) {
        this.movieHistoryRepository = movieHistoryRepository;
        this.userRepository = userRepository;
        this.userService = userService;
    }

    public List<MovieHistoryDTO> getHistory() {
        UserDTO userDto = userService.getUserDTOSignedIn();
        User user = userRepository.findById(userDto.getId())
                .orElseThrow(() -> new UserNotFoundException("User not found", HttpStatus.NOT_FOUND));

        List<MovieHistory> historyList = movieHistoryRepository.findByUserOrderByDownloadedAtDesc(user);

        return historyList.stream().map(this::convertToDto).collect(Collectors.toList());
    }

    public MovieHistoryDTO addToHistory(MovieDTO movieDto) {
        UserDTO userDto = userService.getUserDTOSignedIn();
        User user = userRepository.findById(userDto.getId())
                .orElseThrow(() -> new UserNotFoundException("User not found", HttpStatus.NOT_FOUND));

        MovieHistory history = new MovieHistory();
        history.setUser(user);
        history.setTitle(movieDto.getTitle());
        history.setDescription(movieDto.getDescription());
        history.setLink(movieDto.getLink());
        history.setMovieSize(movieDto.getSize());
        history.setSeeders(movieDto.getSeeders());
        history.setPeers(movieDto.getPeers());
        history.setTracker(movieDto.getTracker());
        history.setTrackerId(movieDto.getTrackerId());
        history.setPublishDate(movieDto.getPublishDate());
        history.setCategory(movieDto.getCategory() != null ? String.join(",", movieDto.getCategory()) : null);
        history.setCategoryDesc(movieDto.getCategoryDesc());
        history.setDetails(movieDto.getDetails());
        history.setMagnetUri(movieDto.getMagnetUri());
        history.setDownloadedAt(LocalDateTime.now());

        MovieHistory saved = movieHistoryRepository.save(history);
        return convertToDto(saved);
    }

    public void removeFromHistory(Long id) {
        UserDTO userDto = userService.getUserDTOSignedIn();
        MovieHistory history = movieHistoryRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "History item not found"));

        if (!history.getUser().getId().equals(userDto.getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Not authorized to delete this item");
        }

        movieHistoryRepository.delete(history);
    }

    private MovieHistoryDTO convertToDto(MovieHistory history) {
        MovieHistoryDTO dto = new MovieHistoryDTO();
        dto.setId(history.getId());
        dto.setDownloadedAt(history.getDownloadedAt());

        MovieDTO movie = new MovieDTO();
        movie.setTitle(history.getTitle());
        movie.setDescription(history.getDescription());
        movie.setLink(history.getLink());
        movie.setSize(history.getMovieSize());
        movie.setSeeders(history.getSeeders());
        movie.setPeers(history.getPeers());
        movie.setTracker(history.getTracker());
        movie.setTrackerId(history.getTrackerId());
        movie.setPublishDate(history.getPublishDate());
        movie.setCategoryDesc(history.getCategoryDesc());
        movie.setDetails(history.getDetails());
        movie.setMagnetUri(history.getMagnetUri());

        if (history.getCategory() != null && !history.getCategory().isEmpty()) {
            movie.setCategory(Arrays.asList(history.getCategory().split(",")));
        }

        dto.setMovie(movie);
        return dto;
    }
}

