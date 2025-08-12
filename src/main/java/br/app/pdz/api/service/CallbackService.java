package br.app.pdz.api.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class CallbackService {
    private final Map<String, String> tempCallbacks = new ConcurrentHashMap<>();
    private final Map<String, String> stateMapping = new ConcurrentHashMap<>();

    public void storeCallback(String sessionId, String callback) {
        log.info("Armazenando callback - Session ID: {}, Callback: {}", sessionId, callback);
        tempCallbacks.put(sessionId, callback);
        log.info("Total de callbacks armazenados: {}", tempCallbacks.size());

        // Remove após 10 minutos para evitar vazamento de memória
        CompletableFuture.delayedExecutor(10, TimeUnit.MINUTES)
            .execute(() -> {
                String removed = tempCallbacks.remove(sessionId);
                log.info("Callback removido automaticamente após 10 minutos - Session ID: {}, Callback: {}", sessionId, removed);
            });
    }

    public String getAndRemoveCallback(String sessionId) {
        String callback = tempCallbacks.remove(sessionId);
        log.info("Recuperando callback - Session ID: {}, Callback encontrado: {}", sessionId, callback);
        log.info("Total de callbacks restantes: {}", tempCallbacks.size());
        return callback;
    }

    public void storeStateMapping(String originalState, String customState) {
        log.info("Armazenando mapeamento de state - Original: {}, Custom: {}", originalState, customState);
        stateMapping.put(originalState, customState);

        // Remove após 10 minutos
        CompletableFuture.delayedExecutor(10, TimeUnit.MINUTES)
            .execute(() -> {
                String removed = stateMapping.remove(originalState);
                log.info("Mapeamento de state removido após 10 minutos - Original: {}, Custom: {}", originalState, removed);
            });
    }

    public String getCallbackByOriginalState(String originalState) {
        String customState = stateMapping.remove(originalState);
        log.info("Recuperando callback usando state original: {} -> custom: {}", originalState, customState);

        if (customState != null) {
            return getAndRemoveCallback(customState);
        }

        return null;
    }
}
