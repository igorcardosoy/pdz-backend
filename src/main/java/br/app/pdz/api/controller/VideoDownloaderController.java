package br.app.pdz.api.controller;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/pdz-api/videos")
public class VideoDownloaderController {

    @GetMapping("/download")
    public void downloadFromYoutube(@RequestParam String videoUrl, HttpServletResponse response) {
        Process process = null;
        File tempFile = null;

        try {
            String ytDlpPath = "C:\\yt-dlp\\yt-dlp.exe";

            File ytDlp = new File(ytDlpPath);
            if (!ytDlp.exists()) {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.getWriter().write("yt-dlp não encontrado no caminho: " + ytDlpPath);
                return;
            }

            String timestamp = String.valueOf(System.currentTimeMillis());
            tempFile = File.createTempFile("video-" + timestamp + "-", ".mp4");
            String outputPath = tempFile.getAbsolutePath();

            System.out.println("Iniciando download para: " + outputPath);

            ProcessBuilder pb = new ProcessBuilder(
                    ytDlpPath,
                    "-f", "best[height<=720]",
                    "--merge-output-format", "mp4",
                    "--no-check-certificate",
                    "--ignore-errors",
                    "--no-warnings",
                    "--force-overwrites",
                    "--no-part",
                    "--socket-timeout", "30",
                    "--retries", "3",
                    "--output", outputPath,
                    videoUrl
            );

            pb.redirectErrorStream(true);
            process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("yt-dlp: " + line);
                    output.append(line).append("\n");
                }
            }

            boolean finished = process.waitFor(3, TimeUnit.MINUTES);
            if (!finished) {
                process.destroyForcibly();
                throw new RuntimeException("Timeout no download do vídeo");
            }

            int exitCode = process.exitValue();

            if (!tempFile.exists() || tempFile.length() == 0) {
                System.err.println("Arquivo vazio ou não existe. Exit code: " + exitCode);
                System.err.println("Output: " + output.toString());
            }

            if (tempFile.length() < 1024) {
                System.err.println("Arquivo muito pequeno: " + tempFile.length() + " bytes");
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.getWriter().write("Arquivo de vídeo muito pequeno, possivelmente corrompido");
                return;
            }

            System.out.println("Download concluído. Tamanho do arquivo: " + tempFile.length() + " bytes");

            response.setContentType("video/mp4");
            response.setHeader("Content-Disposition", "attachment; filename=\"video.mp4\"");
            response.setHeader("Content-Length", String.valueOf(tempFile.length()));
            response.setHeader("Cache-Control", "no-cache");

            try (InputStream in = new FileInputStream(tempFile);
                 OutputStream out = response.getOutputStream()) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
                out.flush();
            }

        } catch (Exception e) {
            e.printStackTrace();
            try {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.getWriter().write("Erro interno: " + e.getMessage());
            } catch (IOException ioException) {
                ioException.printStackTrace();
            }
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }

            if (tempFile != null && tempFile.exists()) {
                try {
                    tempFile.delete();
                } catch (Exception e) {
                    System.err.println("Erro ao deletar arquivo temporário: " + e.getMessage());
                }
            }
        }
    }
}