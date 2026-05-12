package br.app.pdz.api.service;

import br.app.pdz.api.dto.JackettSearchResponse;
import br.app.pdz.api.dto.MovieDTO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.*;
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

            List<MovieDTO> groupedResults = groupByMagnet(filteredResults);

            response.setResults(groupedResults);
            log.info("Found {} grouped movies for query: {} (filtered from {})",
                    groupedResults.size(), query, filteredResults.size());

            return response;
        } catch (Exception e) {
            log.error("Error searching movies in Jackett for query: {}", query, e);
            throw new RuntimeException("Error searching movies in Jackett: " + e.getMessage(), e);
        }
    }

    private List<MovieDTO> groupByMagnet(List<MovieDTO> movies) {
        Map<String, List<MovieDTO>> groupedByMagnet = movies.stream()
                .filter(movie -> movie.getMagnetUri() != null && !movie.getMagnetUri().isBlank())
                .collect(Collectors.groupingBy(MovieDTO::getMagnetUri, LinkedHashMap::new, Collectors.toList()));

        List<MovieDTO> result = new ArrayList<>();
        Set<MovieDTO> withoutMagnet = new LinkedHashSet<>();

        for (MovieDTO movie : movies) {
            if (movie.getMagnetUri() == null || movie.getMagnetUri().isBlank()) {
                withoutMagnet.add(movie);
            }
        }

        for (List<MovieDTO> group : groupedByMagnet.values()) {
            result.add(mergeGroup(group));
        }

        result.addAll(withoutMagnet);
        return result;
    }

    private MovieDTO mergeGroup(List<MovieDTO> group) {
        MovieDTO base = group.get(0);

        List<String> titles = group.stream()
                .map(MovieDTO::getTitle)
                .filter(title -> title != null && !title.isBlank())
                .distinct()
                .collect(Collectors.toList());

        List<String> providers = group.stream()
                .map(movie -> movie.getTracker() != null && !movie.getTracker().isBlank() ? movie.getTracker() : movie.getTrackerId())
                .filter(provider -> provider != null && !provider.isBlank())
                .distinct()
                .collect(Collectors.toList());

        base.setTitles(titles);
        base.setProviders(providers);
        base.setTitle(titles.isEmpty() ? base.getTitle() : chooseBestTitle(titles));
        base.setSize(group.stream().map(MovieDTO::getSize).filter(Objects::nonNull).max(Long::compareTo).orElse(base.getSize()));
        base.setSeeders(group.stream().map(MovieDTO::getSeeders).filter(Objects::nonNull).max(Integer::compareTo).orElse(base.getSeeders()));
        base.setPeers(group.stream().map(MovieDTO::getPeers).filter(Objects::nonNull).max(Integer::compareTo).orElse(base.getPeers()));
        base.setCategory(group.stream()
                .map(MovieDTO::getCategory)
                .filter(Objects::nonNull)
                .flatMap(List::stream)
                .distinct()
                .collect(Collectors.toList()));

        return base;
    }

    private String chooseBestTitle(List<String> titles) {
        return titles.stream()
                .min(Comparator.comparingInt(String::length))
                .orElse(titles.get(0));
    }

    private boolean hasExcludedCategory(MovieDTO movie, List<String> excludedCategories) {
        if (movie.getCategory() == null || movie.getCategory().isEmpty()) {
            return false;
        }

        return movie.getCategory().stream()
                .anyMatch(excludedCategories::contains);
    }
}



