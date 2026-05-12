package br.app.pdz.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
public class MovieDTO {

    @JsonProperty("Title")
    private String title;

    @JsonProperty("Titles")
    private List<String> titles;

    @JsonProperty("Providers")
    private List<String> providers;

    @JsonProperty("Description")
    private String description;

    @JsonProperty("Link")
    private String link;

    @JsonProperty("Size")
    private Long size;

    @JsonProperty("Seeders")
    private Integer seeders;

    @JsonProperty("Peers")
    private Integer peers;

    @JsonProperty("Tracker")
    private String tracker;

    @JsonProperty("TrackerId")
    private String trackerId;

    @JsonProperty("PublishDate")
    private String publishDate;

    @JsonProperty("Category")
    private List<String> category;

    @JsonProperty("CategoryDesc")
    private String categoryDesc;

    @JsonProperty("Details")
    private String details;

    @JsonProperty("MagnetUri")
    private String magnetUri;
}
