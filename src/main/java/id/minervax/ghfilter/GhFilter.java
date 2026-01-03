import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.ConnectionHandshakeEvent;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.proxy.ProxyServer;
import net.kyori.adventure.text.Component;
import org.slf4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Plugin(
        id = "ghfilter",
        name = "GhFilter",
        version = "1.1.0",
        description = "Connection flood + incomplete-handshake filter for Velocity",
        authors = {"gha"}
)
public final class GhFilter {

    private final ProxyServer proxy;
    private final Logger logger;

    // config
    private volatile long windowMs = 5000;
    private volatile int maxAttempts = 4;
    private volatile int maxConcurrent = 2;
    private volatile long banMs = 60_000;
    private volatile String kickMessage = "terlalu banyak koneksi, coba lagi nanti.";

    // incomplete-handshake detection
    private volatile long handshakeTimeoutMs = 800;
    private volatile int maxIncompletePerWindow = 3;

    // metrics
    private volatile int metricsIntervalSec = 10;

    // alert
    private volatile int attackBlockThreshold = 25;
    private volatile long attackAlertCooldownMs = 60_000;

    // discord webhook
    private volatile String webhookUrl = "";
    private volatile String webhookUsername = "GhFilter";
    private volatile String webhookTitle = "⚠️ attack detected";
    private volatile int webhookRedColor = 16711680;

    private final Map<InetAddress, IpState> states = new ConcurrentHashMap<>();
    private Path dataDir;

    // rolling metrics counters
    private final AtomicLong mAttempts = new AtomicLong(0);
    private final AtomicLong mBlocked = new AtomicLong(0);
    private final AtomicLong mBanned = new AtomicLong(0);
    private final AtomicLong mHandshakeOk = new AtomicLong(0);
    private final AtomicLong mHandshakeIncomplete = new AtomicLong(0);

    private final AtomicLong lastAlertAtMs = new AtomicLong(0);
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    @Inject
    public GhFilter(ProxyServer proxy, Logger logger) {
        this.proxy = proxy;
        this.logger = logger;
    }

    @Subscribe
    public void onInit(ProxyInitializeEvent e) {
        dataDir = Path.of("plugins", "ghfilter");
        try {
            Files.createDirectories(dataDir);
        } catch (IOException ex) {
            logger.error("failed creating data dir: {}", dataDir, ex);
        }

        loadOrCreateConfig();

        // cleanup stale states
        proxy.getScheduler().buildTask(this, () -> {
            long now = System.currentTimeMillis();
            states.entrySet().removeIf(en -> en.getValue().isStale(now, windowMs, banMs));
        }).repeat(Duration.ofSeconds(30)).schedule();

        // metrics logger
        proxy.getScheduler().buildTask(this, () -> {
            long a = mAttempts.getAndSet(0);
            long b = mBlocked.getAndSet(0);
            long bn = mBanned.getAndSet(0);
            long ok = mHandshakeOk.getAndSet(0);
            long inc = mHandshakeIncomplete.getAndSet(0);

            if (a == 0 && b == 0 && inc == 0) return;

            logger.info("[GhFilter metrics] attempts={} blocked={} tempbans={} handshake_ok={} handshake_incomplete={}",
                    a, b, bn, ok, inc);

            // attack alert decision based on blocked in this interval
            if (b >= attackBlockThreshold) {
                maybeSendDiscordAlert(b, a, inc);
            }
        }).repeat(Duration.ofSeconds(Math.max(5, metricsIntervalSec))).schedule();

        logger.info("GhFilter enabled: windowMs={} maxAttempts={} maxConcurrent={} banMs={} handshakeTimeoutMs={} maxIncompletePerWindow={}",
                windowMs, maxAttempts, maxConcurrent, banMs, handshakeTimeoutMs, maxIncompletePerWindow);
    }

    @Subscribe
    public void onPreLogin(PreLoginEvent e) {
        InetAddress ip = inet(e.getConnection().getRemoteAddress());
        if (ip == null) return;

        long now = System.currentTimeMillis();
        IpState st = states.computeIfAbsent(ip, _k -> new IpState());

        mAttempts.incrementAndGet();

        // banned?
        if (st.bannedUntilMs > now) {
            mBlocked.incrementAndGet();
            e.setResult(PreLoginEvent.PreLoginComponentResult.denied(Component.text(kickMessage)));
            return;
        }

        // sliding window reset
        st.rollWindowIfNeeded(now, windowMs);

        st.attemptsInWindow++;
        st.activeConnections++;
        st.lastSeenMs = now;

        // mark "pending handshake" so we can count incomplete ones
        st.pendingHandshakes++;

        boolean violateRate = st.attemptsInWindow > maxAttempts;
        boolean violateConc = st.activeConnections > maxConcurrent;

        if (violateRate || violateConc) {
            applyTempBan(st, now, ip, violateConc ? "max_concurrent" : "rate_limit");
            mBlocked.incrementAndGet();
            e.setResult(PreLoginEvent.PreLoginComponentResult.denied(Component.text(kickMessage)));
        }
    }

    /**
     * Handshake happened (client successfully established a handshake intent with the proxy).
     * This does not provide raw bytes; we use it as a signal that the connection wasn't "null/garbage".
     */
    @Subscribe
    public void onHandshake(ConnectionHandshakeEvent e) {
        InetAddress ip = inet(e.getConnection().getRemoteAddress());
        if (ip == null) return;

        IpState st = states.get(ip);
        if (st == null) return;

        long now = System.currentTimeMillis();
        st.lastSeenMs = now;

        // mark one handshake as "ok"
        if (st.pendingHandshakes > 0) st.pendingHandshakes--;
        mHandshakeOk.incrementAndGet();
    }

    @Subscribe
    public void onDisconnect(DisconnectEvent e) {
        InetAddress ip = inet(e.getPlayer().getRemoteAddress());
        if (ip == null) return;

        IpState st = states.get(ip);
        if (st != null) {
            st.activeConnections = Math.max(0, st.activeConnections - 1);
            st.lastSeenMs = System.currentTimeMillis();
        }
    }

    private void applyTempBan(IpState st, long now, InetAddress ip, String reason) {
        st.bannedUntilMs = now + banMs;
        st.attemptsInWindow = 0;
        st.incompleteInWindow = 0;
        st.windowStartMs = now;
        st.pendingHandshakes = 0;
        st.activeConnections = Math.max(0, st.activeConnections - 1);

        mBanned.incrementAndGet();
        logger.warn("[GhFilter] blocked ip={} reason={} until={} ",
                ip.getHostAddress(), reason, Instant.ofEpochMilli(st.bannedUntilMs));
    }

    private void maybeSendDiscordAlert(long blocked, long attempts, long incomplete) {
        if (webhookUrl == null || webhookUrl.isBlank()) return;

        long now = System.currentTimeMillis();
        long last = lastAlertAtMs.get();
        if (now - last < attackAlertCooldownMs) return;
        if (!lastAlertAtMs.compareAndSet(last, now)) return;

        String desc =
                "**status:** attack-like traffic detected\n" +
                "**blocked (interval):** " + blocked + "\n" +
                "**attempts (interval):** " + attempts + "\n" +
                "**incomplete-handshake (interval):** " + incomplete + "\n" +
                "**time:** " + Instant.ofEpochMilli(now);

        // minimal webhook JSON (embed merah)
        String json = "{"
                + "\"username\":\"" + escape(webhookUsername) + "\","
                + "\"embeds\":[{"
                + "\"title\":\"" + escape(webhookTitle) + "\","
                + "\"description\":\"" + escape(desc) + "\","
                + "\"color\":" + webhookRedColor
                + "}]"
                + "}";

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(webhookUrl))
                .timeout(Duration.ofSeconds(8))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
                .build();

        http.sendAsync(req, HttpResponse.BodyHandlers.discarding())
                .whenComplete((resp, err) -> {
                    if (err != null) {
                        logger.warn("[GhFilter] discord webhook failed: {}", err.toString());
                        return;
                    }
                    int code = resp.statusCode();
                    if (code < 200 || code >= 300) {
                        logger.warn("[GhFilter] discord webhook http status={}", code);
                    }
                });
    }

    private InetAddress inet(SocketAddress addr) {
        if (addr instanceof InetSocketAddress isa) return isa.getAddress();
        return null;
    }

    private void loadOrCreateConfig() {
        Path cfg = dataDir.resolve("config.yml");

        if (!Files.exists(cfg)) {
            try (InputStream in = getClass().getClassLoader().getResourceAsStream("config.yml")) {
                if (in == null) {
                    logger.warn("default config.yml not found in resources");
                } else {
                    Files.copy(in, cfg);
                    logger.info("created default config at {}", cfg);
                }
            } catch (IOException ex) {
                logger.error("failed writing default config", ex);
            }
        }

        try {
            for (String line : Files.readAllLines(cfg, StandardCharsets.UTF_8)) {
                String t = line.trim();
                if (t.isEmpty() || t.startsWith("#")) continue;
                int idx = t.indexOf(':');
                if (idx < 0) continue;

                String key = t.substring(0, idx).trim();
                String val = t.substring(idx + 1).trim();

                if ((val.startsWith("\"") && val.endsWith("\"")) || (val.startsWith("'") && val.endsWith("'"))) {
                    val = val.substring(1, val.length() - 1);
                }

                switch (key) {
                    case "window_ms" -> windowMs = parseLong(val, windowMs);
                    case "max_attempts_per_window" -> maxAttempts = (int) parseLong(val, maxAttempts);
                    case "max_concurrent" -> maxConcurrent = (int) parseLong(val, maxConcurrent);
                    case "ban_seconds" -> banMs = parseLong(val, 60) * 1000L;
                    case "kick_message" -> kickMessage = val.isEmpty() ? kickMessage : val;

                    case "handshake_timeout_ms" -> handshakeTimeoutMs = parseLong(val, handshakeTimeoutMs);
                    case "max_incomplete_per_window" -> maxIncompletePerWindow = (int) parseLong(val, maxIncompletePerWindow);

                    case "metrics_log_interval_seconds" -> metricsIntervalSec = (int) parseLong(val, metricsIntervalSec);

                    case "attack_block_threshold" -> attackBlockThreshold = (int) parseLong(val, attackBlockThreshold);
                    case "attack_alert_cooldown_seconds" -> attackAlertCooldownMs = parseLong(val, 60) * 1000L;

                    case "discord_webhook_url" -> webhookUrl = val;
                    case "discord_username" -> webhookUsername = val.isEmpty() ? webhookUsername : val;
                    case "discord_embed_title" -> webhookTitle = val.isEmpty() ? webhookTitle : val;
                    case "discord_embed_color_red" -> webhookRedColor = (int) parseLong(val, webhookRedColor);
                }
            }
        } catch (IOException ex) {
            logger.error("failed reading config {}", cfg, ex);
        }

        // clamps
        windowMs = Math.max(500, windowMs);
        maxAttempts = Math.max(1, maxAttempts);
        maxConcurrent = Math.max(1, maxConcurrent);
        banMs = Math.max(1000, banMs);

        handshakeTimeoutMs = Math.max(100, handshakeTimeoutMs);
        maxIncompletePerWindow = Math.max(1, maxIncompletePerWindow);

        metricsIntervalSec = Math.max(5, metricsIntervalSec);
        attackBlockThreshold = Math.max(1, attackBlockThreshold);
        attackAlertCooldownMs = Math.max(10_000, attackAlertCooldownMs);
    }

    private long parseLong(String s, long fallback) {
        try { return Long.parseLong(s); } catch (Exception ignored) { return fallback; }
    }

    private String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "");
    }

    // ---- state ----
    private final class IpState {
        volatile long windowStartMs = 0;
        volatile int attemptsInWindow = 0;

        volatile int activeConnections = 0;
        volatile long bannedUntilMs = 0;
        volatile long lastSeenMs = 0;

        // handshake tracking
        volatile int pendingHandshakes = 0;
        volatile int incompleteInWindow = 0;

        void rollWindowIfNeeded(long now, long windowMs) {
            if (windowStartMs == 0) {
                windowStartMs = now;
                attemptsInWindow = 0;
                incompleteInWindow = 0;
                return;
            }
            if (now - windowStartMs > windowMs) {
                windowStartMs = now;
                attemptsInWindow = 0;
                incompleteInWindow = 0;
            }
        }

        boolean isStale(long now, long windowMs, long banMs) {
            long idle = now - lastSeenMs;
            return idle > Math.max(120_000, windowMs + banMs);
        }
    }

    // run in background to convert pending handshakes into "incomplete"
    @Subscribe
    public void onProxyReady(ProxyInitializeEvent e) {
        proxy.getScheduler().buildTask(this, () -> {
            long now = System.currentTimeMillis();

            for (Map.Entry<InetAddress, IpState> en : states.entrySet()) {
                InetAddress ip = en.getKey();
                IpState st = en.getValue();

                if (st.pendingHandshakes <= 0) continue;
                if (st.bannedUntilMs > now) continue;

                // if lastSeen too old beyond handshakeTimeout, treat as incomplete
                // (we approximate: if connection didn't handshake quickly, it's likely garbage/null/invalid)
                if (now - st.lastSeenMs >= handshakeTimeoutMs) {
                    st.rollWindowIfNeeded(now, windowMs);

                    int consume = st.pendingHandshakes;
                    st.pendingHandshakes = 0;

                    st.incompleteInWindow += consume;
                    mHandshakeIncomplete.addAndGet(consume);

                    if (st.incompleteInWindow > maxIncompletePerWindow) {
                        applyTempBan(st, now, ip, "incomplete_handshake");
                        // count as blocked burst
                        mBlocked.addAndGet(consume);
                    }
                }
            }
        }).repeat(Duration.ofMillis(Math.max(200, handshakeTimeoutMs / 2))).schedule();
    }
}
EOF
