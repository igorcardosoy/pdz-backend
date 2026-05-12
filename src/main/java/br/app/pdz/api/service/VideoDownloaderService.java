package br.app.pdz.api.service;

import br.app.pdz.api.dto.VideoDownloadRequest;
import br.app.pdz.api.dto.VideoInfoDTO;
import br.app.pdz.api.dto.FormatInfoDTO;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.*;
import java.util.concurrent.TimeUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Slf4j
@Service
public class VideoDownloaderService {

    private static final String YT_DLP_PATH = "/home/igorcardosoy/yt-dlp/yt-dlp_linux";
    private static final long MIN_FILE_SIZE = 1024; // 1KB mínimo
    private static final long DOWNLOAD_TIMEOUT_MINUTES = 3;

    private final ObjectMapper objectMapper;

    public VideoDownloaderService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public VideoInfoDTO getVideoInfo(String videoUrl) {
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    YT_DLP_PATH,
                    "--dump-json",
                    "--no-warnings",
                    videoUrl
            );

            Process process = pb.start();
            JsonNode rootNode = objectMapper.readTree(process.getInputStream());

            String title = rootNode.has("title") ? rootNode.get("title").asText() : "video";
            int duration = rootNode.has("duration") ? rootNode.get("duration").asInt() : 0;
            JsonNode formatsNode = rootNode.get("formats");

            List<FormatInfoDTO> formatList = new ArrayList<>();
            Map<String, FormatInfoDTO> uniqueVideoFormats = new HashMap<>();

            if (formatsNode != null && formatsNode.isArray()) {
                double bestAudioSize = 0.0;
                for (JsonNode format : formatsNode) {
                    if (format.has("vcodec") && "none".equals(format.get("vcodec").asText()) && format.has("acodec") && !"none".equals(format.get("acodec").asText())) {
                        double size = getFileSizeInMb(format);
                        if (size > bestAudioSize) bestAudioSize = size;
                    }
                }

                if (bestAudioSize > 0) {
                    formatList.add(new FormatInfoDTO("audio", "mp3", bestAudioSize));
                    formatList.add(new FormatInfoDTO("audio", "wav", bestAudioSize * 2.5)); // estimativa aproximada para wav
                }

                for (JsonNode format : formatsNode) {
                    if (format.has("height") && !format.get("height").isNull()) {
                        int height = format.get("height").asInt();
                        if (height > 0 && format.has("vcodec") && !"none".equals(format.get("vcodec").asText())) {
                            String resKey = height + "p";
                            double sizeMb = getFileSizeInMb(format);

                            if (!uniqueVideoFormats.containsKey(resKey) || uniqueVideoFormats.get(resKey).sizeMb() < sizeMb) {
                                uniqueVideoFormats.put(resKey, new FormatInfoDTO(resKey, "mp4", Math.round((sizeMb + bestAudioSize) * 100.0) / 100.0));
                            }
                        }
                    }
                }
            }

            List<FormatInfoDTO> sortedVideos = new ArrayList<>(uniqueVideoFormats.values());
            sortedVideos.sort((f1, f2) -> {
                int h1 = Integer.parseInt(f1.resolution().replace("p", ""));
                int h2 = Integer.parseInt(f2.resolution().replace("p", ""));
                return Integer.compare(h2, h1); // reverse sort
            });

            formatList.addAll(sortedVideos);

            return new VideoInfoDTO(title, duration, formatList);

        } catch (Exception e) {
            log.error("Erro ao obter informações: {}", e.getMessage());
            return new VideoInfoDTO("Desconhecido", 0, List.of());
        }
    }

    private double getFileSizeInMb(JsonNode format) {
        long bytes = 0;
        if (format.has("filesize") && !format.get("filesize").isNull()) {
            bytes = format.get("filesize").asLong();
        } else if (format.has("filesize_approx") && !format.get("filesize_approx").isNull()) {
            bytes = format.get("filesize_approx").asLong();
        }
        return Math.round((bytes / 1048576.0) * 100.0) / 100.0;
    }

    public void downloadAndStreamVideo(VideoDownloadRequest videoDownloadRequest, HttpServletResponse response) {
        Process process = null;
        File tempFile;

        try {
            File ytDlp = new File(YT_DLP_PATH);
            if (!ytDlp.exists()) {
                sendErrorResponse(response, "yt-dlp não encontrado no caminho: " + YT_DLP_PATH);
                return;
            }

            String title = "download";
            try {
                ProcessBuilder pbTitle = new ProcessBuilder(YT_DLP_PATH, "--print", "title", videoDownloadRequest.url());
                Process pTitle = pbTitle.start();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(pTitle.getInputStream()))) {
                    String t = reader.readLine();
                    if (t != null && !t.isBlank()) {
                        title = t.replaceAll("[\\\\/:*?\"<>|]", "_");
                    }
                }
            } catch (Exception e) {
                log.warn("Não foi possível obter o título do vídeo. Usando nome padrão.");
            }

            String extension = videoDownloadRequest.format() != null ? videoDownloadRequest.format().toLowerCase() : "mp4";

            String timestamp = String.valueOf(System.currentTimeMillis());
            tempFile = File.createTempFile("video-" + timestamp + "-", "." + extension);
            String outputPath = tempFile.getAbsolutePath();

            String resolution = videoDownloadRequest.resolution() != null ? videoDownloadRequest.resolution().replaceAll("[^0-9]", "") : "720";

            var pb = getProcessBuilder(videoDownloadRequest.url(), outputPath, resolution, extension);
            process = pb.start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                while (reader.readLine() != null) {
                    // Ignora logs excessivos
                }
            }

            boolean finished = process.waitFor(DOWNLOAD_TIMEOUT_MINUTES, TimeUnit.MINUTES);
            if (!finished) {
                process.destroyForcibly();
                sendErrorResponse(response, "Timeout no download do vídeo");
                return;
            }

            int exitCode = process.exitValue();

            if (!tempFile.exists() || tempFile.length() == 0) {
                log.error("Arquivo vazio ou não existe. Exit code: {}", exitCode);
                sendErrorResponse(response, "Arquivo de vídeo não foi criado ou está vazio");
                return;
            }

            if (tempFile.length() < MIN_FILE_SIZE) {
                log.error("Arquivo muito pequeno: {} bytes", tempFile.length());
                sendErrorResponse(response, "Arquivo de vídeo muito pequeno, possivelmente corrompido");
                return;
            }

            log.info("Download concluído. Tamanho do arquivo: {} bytes", tempFile.length());

            streamFile(tempFile, title + "." + extension, response);

        } catch (Exception e) {
            log.error("Erro ao baixar arquivo: ", e);
            sendErrorResponse(response, "Erro interno: " + e.getMessage());
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }

    private void streamFile(File file, String finalFileName, HttpServletResponse response) {
        try {
            String encodedFileName = URLEncoder.encode(finalFileName, StandardCharsets.UTF_8).replace("+", "%20");

            String contentType = "application/octet-stream";
            if (finalFileName.endsWith(".mp4")) contentType = "video/mp4";
            else if (finalFileName.endsWith(".mp3")) contentType = "audio/mpeg";
            else if (finalFileName.endsWith(".wav")) contentType = "audio/wav";

            response.setContentType(contentType);
            response.setHeader("Content-Disposition", "attachment; filename*=UTF-8''" + encodedFileName);
            response.setHeader("Content-Length", String.valueOf(file.length()));
            response.setHeader("Cache-Control", "no-cache");

            try (InputStream in = new FileInputStream(file);
                 OutputStream out = response.getOutputStream()) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
                out.flush();
            }
        } catch (IOException e) {
            log.error("Erro ao enviar arquivo: {}", e.getMessage());
        } finally {
            if (file.exists()) {
                try {
                    if (file.delete()) {
                        log.debug("Arquivo temporário deletado: {}", file.getAbsolutePath());
                    } else {
                        log.warn("Falha ao deletar arquivo temporário: {}", file.getAbsolutePath());
                    }
                } catch (Exception e) {
                    log.error("Erro ao deletar arquivo temporário: ", e);
                }
            }
        }
    }

    private void sendErrorResponse(HttpServletResponse response, String message) {
        try {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"" + message + "\"}");
        } catch (IOException e) {
            log.error("Erro ao enviar resposta de erro: {}", e.getMessage());
        }
    }

    private ProcessBuilder getProcessBuilder(String videoUrl, String outputPath, String resolution, String targetFormat) {
        List<String> commands = new ArrayList<>();
        commands.add(YT_DLP_PATH);

        if ("mp3".equals(targetFormat) || "wav".equals(targetFormat)) {
            commands.add("-x");
            commands.add("--audio-format");
            commands.add(targetFormat);
            commands.add("-f");
            commands.add("bestaudio");
        } else {
            commands.add("-f");
            commands.add("bestvideo[height<=" + resolution + "][ext=mp4]+bestaudio[ext=m4a]/best[height<=" + resolution + "][ext=mp4]/best");
            commands.add("--merge-output-format");
            commands.add("mp4");
        }

        commands.add("--no-check-certificate");
        commands.add("--ignore-errors");
        commands.add("--no-warnings");
        commands.add("--force-overwrites");
        commands.add("--no-part");
        commands.add("--socket-timeout");
        commands.add("30");
        commands.add("--retries");
        commands.add("3");
        commands.add("--output");
        commands.add(outputPath);
        commands.add(videoUrl);

        ProcessBuilder pb = new ProcessBuilder(commands);
        pb.redirectErrorStream(true);
        return pb;
    }
}

