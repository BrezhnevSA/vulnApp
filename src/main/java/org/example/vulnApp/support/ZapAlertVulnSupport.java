package org.example.vulnApp.support;

import java.util.Locale;
import java.util.regex.Pattern;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

public final class ZapAlertVulnSupport {
    public static final long TIMING_MARGIN_MS = 1_500L;
    public static final double MAX_SLEEP_SECONDS = 60.0;

    public static final Pattern POSTGRES_SLEEP_PATTERN = Pattern.compile(
        "^case\\s+when\\s+cast\\(pg_sleep\\((\\d+)(?:\\.\\d+)?\\)\\s+as\\s+varchar\\)"
            + "\\s+>\\s+''\\s+then\\s+0\\s+else\\s+1\\s+end"
    );

    public static final Pattern ORACLE_SLEEP_PATTERN = Pattern.compile(
        "DBMS_(?:SESSION|LOCK)\\s*\\.\\s*SLEEP\\s*\\(\\s*(\\d+(?:\\.\\d+)?)\\s*\\)",
        Pattern.CASE_INSENSITIVE
    );

    public static final long LEGACY_ORACLE_SLEEP_MS = 5_000L;

    public static final Pattern MYSQL_SLEEP_PATTERN = Pattern.compile(
        "(?i)(?<![A-Za-z0-9_.])sleep\\s*\\(\\s*(\\d+(?:\\.\\d+)?)\\s*\\)|(?<![A-Za-z0-9_.])benchmark\\s*\\("
    );

    public static final Pattern HSQL_SLEEP_PATTERN = Pattern.compile(
        "(?i)(?:call\\s+sleep\\s*\\(\\s*(\\d+(?:\\.\\d+)?)\\s*\\)|java\\.lang\\.thread\\.sleep\\s*\\(\\s*(\\d+)\\s*\\))"
    );

    public static final Pattern MSSQL_WAITFOR_PATTERN = Pattern.compile(
        "(?i)waitfor\\s+delay\\s+'0+:0+:(\\d+(?:\\.\\d+)?)'"
    );

    public static final Pattern SQLITE_RANDOMBLOB_PATTERN = Pattern.compile(
        "randomblob\\s*\\(\\s*(\\d+)\\s*\\)",
        Pattern.CASE_INSENSITIVE
    );

    public static final long SQLITE_MIN_RANDOMBLOB_BYTES = 100_000L;
    public static final long SQLITE_MAX_SLEEP_MS = 8_000L;

    public static final Pattern OS_COMMAND_SLEEP_PATTERN = Pattern.compile(
        "(?i)(?:^|[;&|`\\s])(?:sleep\\s+(\\d{1,2})(?:\\b|\\s|$)|timeout(?:\\.exe)?\\s+(?:/t\\s+)?(\\d{1,2})(?:\\b|\\s|$)|ping\\s+(?:-c\\s+(\\d{1,2})|(?:127\\.0\\.0\\.1|localhost)\\s+-n\\s+(\\d{1,2})))"
    );

    public static final Pattern SSTI_SLEEP_PATTERN = Pattern.compile(
        "(?i)(?:\\$\\{|#\\{|\\{\\{|<%=).*?(?:thread\\.sleep|sleep)\\s*\\(\\s*(\\d{1,5})\\s*\\)"
    );

    public static final Pattern MONGO_WHERE_SLEEP_PATTERN = Pattern.compile(
        "(?i)\\$where.*?(?:sleep|settimeout)\\s*\\(\\s*(\\d{1,5})\\s*\\)"
    );

    private ZapAlertVulnSupport() {
    }

    public static void sleepSecondsWithMargin(double seconds) {
        double boundedSeconds = Math.min(Math.max(seconds, 0.0), MAX_SLEEP_SECONDS);
        sleepMillis(Math.round(boundedSeconds * 1000.0) + TIMING_MARGIN_MS);
    }
    public static double firstMatchedNumber(java.util.regex.Matcher matcher) {
        for (int i = 1; i <= matcher.groupCount(); i++) {
            String value = matcher.group(i);
            if (value != null) {
                return Double.parseDouble(value);
            }
        }
        return 0.0;
    }

    public static void sleepSecondsOrMillisWithMargin(double value) {
        if (value > MAX_SLEEP_SECONDS) {
            sleepMillis(Math.round(Math.min(value, MAX_SLEEP_SECONDS * 1000.0)) + TIMING_MARGIN_MS);
            return;
        }
        sleepSecondsWithMargin(value);
    }


    public static void sleepMillis(long millis) {
        try {
            Thread.sleep(Math.max(0L, millis));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public static long sqliteRandomblobDelayMillis(long blobBytes) {
        if (blobBytes < SQLITE_MIN_RANDOMBLOB_BYTES) {
            return 0L;
        }
        /*
         * ZAP tries this sequence:
         * randomblob(100000)
         * randomblob(1000000)
         * randomblob(10000000)
         * We need response time to increase, but not exceed ZAP's SQLite timing budget too much.
         */
        double ratio = (double) blobBytes / SQLITE_MIN_RANDOMBLOB_BYTES;
        double step = Math.max(1.0, Math.log10(ratio) + 1.0);
        return Math.min(Math.round(step * 900L), SQLITE_MAX_SLEEP_MS);
    }

    public static String safeLower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }

    public static String escapeXml(String value) {
        return value == null ? "" : value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    public static ResponseEntity<String> text(String body) {
        return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body(body);
    }

    public static ResponseEntity<String> html(String body) {
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(body);
    }

    public static ResponseEntity<String> xml(String body) {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML).body(body);
    }

    public static ResponseEntity<String> json(String body) {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(body);
    }
}
