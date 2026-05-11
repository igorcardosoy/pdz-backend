package br.app.pdz.api.service;

import br.app.pdz.api.dto.JackettSearchResponse;
import br.app.pdz.api.dto.MovieDTO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Service
public class JackettService {

    @Value("${jackett.api.url}")
    private String jackettApiUrl;

    @Value("${jackett.api.key}")
    private String jackettApiKey;

    @Value("${jackett.excluded-categories:6000,6010,6060,100067,100051,100050,100049,100048,6040,6045,6070,100500,100599,100203}")
    private String excludedCategoriesString;

    private final RestTemplate restTemplate;

    public JackettService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public JackettSearchResponse searchMovies(String query, int limit) {
        try {
            String url = String.format("%s/api/v2.0/indexers/all/results", jackettApiUrl);

            Map<String, Object> params = new HashMap<>();
            params.put("query", query);
            params.put("limit", limit);
            params.put("apikey", jackettApiKey);

            JackettSearchResponse response = restTemplate.getForObject(
                    url + "?query={query}&limit={limit}&apikey={apikey}",
                    JackettSearchResponse.class,
                    params
            );

            if (response == null || response.getResults() == null) {
                log.warn("No results from Jackett for query: {}", query);
                return new JackettSearchResponse();
            }

            List<String> excludedCategories = Arrays.asList(excludedCategoriesString.split(","));
            List<MovieDTO> filteredResults = response.getResults().stream()
                    .filter(movie -> !hasExcludedCategory(movie, excludedCategories))
                    .collect(Collectors.toList());

            response.setResults(filteredResults);
            log.info("Found {} movies for query: {} (filtered from {})",
                    filteredResults.size(), query, response.getResults().size());

            return response;
        } catch (Exception e) {
            log.error("Error searching movies in Jackett for query: {}", query, e);
            throw new RuntimeException("Error searching movies in Jackett: " + e.getMessage(), e);
        }
    }

    private boolean hasExcludedCategory(MovieDTO movie, List<String> excludedCategories) {
        if (movie.getCategory() == null || movie.getCategory().isEmpty()) {
            return false;
        }

        return movie.getCategory().stream()
                .anyMatch(excludedCategories::contains);
    }
}



