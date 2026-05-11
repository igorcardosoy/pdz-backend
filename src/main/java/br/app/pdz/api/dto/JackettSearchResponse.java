package br.app.pdz.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
public class JackettSearchResponse {

    @JsonProperty("Results")
    private List<MovieDTO> results;
}

