package br.app.pdz.api.service;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Service
public class CallbackService {
    private final Map<String, String> tempCallbacks = new ConcurrentHashMap<>();

    public void storeCallback(String sessionId, String callback) {
        tempCallbacks.put(sessionId, callback);
        CompletableFuture.delayedExecutor(10, TimeUnit.MINUTES)
            .execute(() -> tempCallbacks.remove(sessionId));
    }

    public String getAndRemoveCallback(String sessionId) {
        return tempCallbacks.remove(sessionId);
    }
}
