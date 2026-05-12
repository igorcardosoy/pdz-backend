package br.app.pdz.api.controller;

import br.app.pdz.api.dto.VideoDownloadRequest;
import br.app.pdz.api.dto.VideoInfoDTO;
import br.app.pdz.api.service.VideoDownloaderService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/pdz-api/videos")
public class VideoDownloaderController {

    private final VideoDownloaderService videoDownloaderService;

    public VideoDownloaderController(VideoDownloaderService videoDownloaderService) {
        this.videoDownloaderService = videoDownloaderService;
    }

    @GetMapping("/info")
    public ResponseEntity<VideoInfoDTO> getVideoInfo(@RequestParam(value = "url", required = false) String url,
                                                     @RequestBody (required = false) VideoDownloadRequest videoDownloadRequest) {
        String videoUrl = (url != null) ? url : (videoDownloadRequest != null ? videoDownloadRequest.url() : null);

        log.info("Buscando informações para o vídeo: {}", videoUrl);
        VideoInfoDTO info = videoDownloaderService.getVideoInfo(videoUrl);
        return ResponseEntity.ok(info);
    }

    @GetMapping("/download")
    public void downloadFromYoutube(@RequestParam(value = "url", required = false) String url,
                                    @RequestParam(value = "resolution", required = false) String resolutionParam,
                                    @RequestParam(value = "format", required = false) String formatParam,
                                    @RequestBody(required = false) VideoDownloadRequest videoDownloadRequest,
                                    HttpServletResponse response) {
        String videoUrl = (url != null) ? url : (videoDownloadRequest != null ? videoDownloadRequest.url() : null);
        String resolution = (resolutionParam != null) ? resolutionParam : (videoDownloadRequest != null ? videoDownloadRequest.resolution() : null);
        String format = (formatParam != null) ? formatParam : (videoDownloadRequest != null ? videoDownloadRequest.format() : null);

        if (videoUrl == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        log.info("Iniciando download de vídeo: {} | resolução: {} | formato: {}", videoUrl,
                 resolution != null ? resolution : "padrão",
                 format != null ? format : "mp4");

        VideoDownloadRequest request = new VideoDownloadRequest(videoUrl, resolution, format);
        videoDownloaderService.downloadAndStreamVideo(request, response);
    }
}