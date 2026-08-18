package org.example.vulnApp;

import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Configuration
@ComponentScan
@EnableAutoConfiguration
public class VulnApp extends SpringBootServletInitializer {
    final static Pattern SLEEP_PATTERN = Pattern.compile(
        "^case\\s+when\\s+cast\\(pg_sleep\\((\\d+)(?:\\.\\d+)?\\)\\s+as\\s+varchar\\)"
            + "\\s+>\\s+''\\s+then\\s+0\\s+else\\s+1\\s+end"
    );

    final static Pattern ORACLE_SLEEP_PATTERN = Pattern.compile(
        "DBMS_(?:SESSION|LOCK)\\s*\\.\\s*SLEEP\\s*\\(\\s*(\\d+(?:\\.\\d+)?)\\s*\\)",
        Pattern.CASE_INSENSITIVE
    );

    final static double MAX_ORACLE_SLEEP_SECONDS = 60.0;

    static final long ORACLE_TIMING_MARGIN_MILLIS = 1500L;

    final static long LEGACY_ORACLE_SLEEP_MILLIS = 5000L;

    final static Pattern SQLITE_RANDOMBLOB_PATTERN = Pattern.compile(
        "randomblob\\s*\\(\\s*(\\d+)\\s*\\)",
        Pattern.CASE_INSENSITIVE
    );

    final static long SQLITE_MIN_RANDOMBLOB_BYTES = 100_000L;
    final static long SQLITE_MAX_SLEEP_MILLIS = 8_000L;

    final Set<String> payloadSent = new HashSet<>();

    final List<SomeObject> commentRepository = new ArrayList<>();

    final List<SomeObject> eventRepository = new CopyOnWriteArrayList<>();

    final List<SomeObject> issueRepository = new ArrayList<>();

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(VulnApp.class);
    }

    public static void main(String[] args) {
        SpringApplication.run(VulnApp.class, args);
    }

    public static class Response {
        public String test;
    }

    public static class SomeObject {
        private Long id;
        private String value;
    }

    @RestController
    public class VulnAppController {

        @Hidden
        @RequestMapping(value = {"/", "/vulnApp"}, method = RequestMethod.GET)
        public ResponseEntity<String> index() {
            return ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                .body(
                    "<html><body>"
                        + "<a href='event'>Stored events</a>"
                        + "<form action='event' method='post'>"
                        + "<input name='value' value='event'><button>Store event</button>"
                        + "</form>"
                        + "<a href='vulnApp/sqlInjectionOracleTimeBased?name=test'>"
                        + "Oracle query</a>"
                        + "<a href='vulnApp/xsltInjection?template=text'>XSLT transform</a>"
                        + "</body></html>"
                );
        }

        // Cross Site Scripting Weakness (Persistent in JSON Response)
        @ApiResponses(
            value = {
                @ApiResponse(
                    content = {
                        @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class)
                        )
                    }
                )
            }
        )
        @RequestMapping(value = "/comment", method = RequestMethod.POST)
        public ResponseEntity<String> addComment(@RequestParam String value) {
            SomeObject comment = new SomeObject();
            comment.id = (long) commentRepository.size();
            comment.value = value;
            commentRepository.add(comment);
            return new ResponseEntity<>(
                "{\"value\":\"" + comment.value + "\",id:" + comment.id + "}",
                HttpStatus.OK
            );
        }

        // Cross Site Scripting Weakness (Persistent in JSON Response)
        @ApiResponses(
            value = {
                @ApiResponse(
                    content = {
                        @Content(
                            array = @ArraySchema(
                                schema = @Schema(implementation = String.class)
                            )
                        )
                    }
                )
            }
        )
        @RequestMapping(value = "/comment", method = RequestMethod.GET)
        public ResponseEntity<List<String>> getComments() {
            return new ResponseEntity<>(
                commentRepository.stream()
                    .map(comment -> "{\"value\":\"" + comment.value + "\",id:" + comment.id + "}")
                    .collect(Collectors.toList()),
                HttpStatus.OK
            );
        }

        // Cross Site Scripting Weakness (Persistent in JSON Response)
        @ApiResponses(
            value = {
                @ApiResponse(
                    content = {
                        @Content(
                            array = @ArraySchema(
                                schema = @Schema(implementation = String.class)
                            )
                        )
                    }
                )
            }
        )
        @RequestMapping(value = "/comment/{id}", method = RequestMethod.GET)
        public ResponseEntity<List<String>> getComment(@PathVariable("id") Long id) {
            return new ResponseEntity<>(
                commentRepository.stream()
                    .filter(comment -> comment.id.equals(id))
                    .map(comment -> "{\"value\":\"" + comment.value + "\",id:" + comment.id + "}")
                    .collect(Collectors.toList()),
                HttpStatus.OK
            );
        }

        // Cross Site Scripting Weakness (Persistent in JSON Response)
        @ApiResponses(
            value = {
                @ApiResponse(
                    content = {
                        @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class)
                        )
                    }
                )
            }
        )
        @RequestMapping(value = "/comment/html", method = RequestMethod.GET)
        public ResponseEntity<String> getCommentsHtml() {
            return new ResponseEntity<>(
                "<html><body>"
                 + commentRepository.stream()
                    .map(comment -> "<p>" + comment.value + " with id:" + comment.id + "</p>")
                    .collect(Collectors.toList())
                + "</body></html>",
                HttpStatus.OK
            );
        }

        // Cross Site Scripting (Persistent)
        @ApiResponses(
            value = {
                @ApiResponse(
                    content = {
                        @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class)
                        )
                    }
                )
            }
        )
        @RequestMapping(value = "/event", method = RequestMethod.POST)
        public ResponseEntity<String> addEvent(@RequestParam String value) {
            SomeObject event = new SomeObject();
            event.id = (long) eventRepository.size();
            event.value = value;
            eventRepository.add(event);
            return new ResponseEntity<>(
                "{\"id\":" + event.id + "}",
                HttpStatus.OK
            );
        }

        // Cross Site Scripting (Persistent)
        @ApiResponses(
            value = {
                @ApiResponse(
                    content = {
                        @Content(
                            mediaType = MediaType.TEXT_HTML_VALUE,
                            schema = @Schema(implementation = String.class)
                        )
                    }
                )
            }
        )
        @RequestMapping(value = "/event", method = RequestMethod.GET)
        public ResponseEntity<String> getEvents() {
            return ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                .body(
                    "<html><body>"
                    + eventRepository.stream()
                    .map(event -> "<p>" + event.value + " with id:" + event.id + "</p>")
                    .collect(Collectors.joining())
                    + "</body></html>"
                );
        }

        // Information Disclosure - Debug Error Messages
        // Application Error Disclosure
        @ApiResponses(
            value = {
                @ApiResponse(
                    content = {
                        @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = Response.class)
                        )
                    }
                )
            }
        )
        @RequestMapping(value = "/issue", method = RequestMethod.POST)
        public SomeObject addIssue(String value) {
            SomeObject issue = new SomeObject();
            issue.id = (long) eventRepository.size();
            issue.value = value;
            issueRepository.add(issue);
            return issue;
        }

        // Information Disclosure - Debug Error Messages
        // Application Error Disclosure
        @ApiResponses(
            value = {
                @ApiResponse(
                    content = {
                        @Content(
                            array = @ArraySchema(
                                schema = @Schema(implementation = Response.class)
                            )
                        )
                    }
                )
            }
        )
        @RequestMapping(value = "/issue", method = RequestMethod.GET)
        public List<SomeObject> getIssues() {
            return commentRepository;
        }

        // Cross Site Scripting Weakness (Reflected in JSON Response)
        @ApiResponses(
            value = {
                @ApiResponse(
                    content = {
                        @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = Response.class)
                        )
                    }
                )
            }
        )
        @RequestMapping(value = "/vulnApp/cssw", method = RequestMethod.GET)
        public ResponseEntity<Response> csswVuln(
            @RequestParam(value = "name") String name
        ) {
            final var result = new Response();
            result.test = "<tr><td>Hello " + name + " !</tr></td>\\n";
            return new ResponseEntity<>(result, HttpStatus.OK);
        }

        // Cross Site Scripting (DOM Based)
        // Cross Site Scripting (Reflected)
        @ApiResponses(
            value = {
                @ApiResponse(
                    content = {
                        @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class)
                        )
                    }
                )
            }
        )
        @RequestMapping(value = "/vulnApp/cssw/html", method = RequestMethod.GET)
        public ResponseEntity<String> csswVulnHtml(
            @RequestParam(value = "name") String name
        ) {
            return new ResponseEntity<>(
                "<tr><td>Hello " + name + " !</tr></td>\\n",
                HttpStatus.OK
            );
        }

        // SQL Injection - Oracle - Time Based
        @ApiResponses(
            value = {
                @ApiResponse(
                    content = {
                        @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = Response.class)
                        )
                    }
                )
            }
        )
        @RequestMapping(
            value = "/vulnApp/sqlInjectionOracleTimeBased",
            method = RequestMethod.GET
        )
        public ResponseEntity<Response> sqlInjectionOracleTimeBasedVuln(
            @RequestParam(value = "name") String name
        ) {
            final var result = new Response();
            result.test = "<html><body></body></html>";
            if (name == null) {
                return new ResponseEntity<>(result, HttpStatus.OK);
            }
            System.out.println("Oracle SQLi param name = " + name);
            final Matcher oracleSleep = ORACLE_SLEEP_PATTERN.matcher(name);
            if (oracleSleep.find()) {
                final double requestedSeconds = Double.parseDouble(oracleSleep.group(1));
                final double boundedSeconds = Math.min(requestedSeconds, MAX_ORACLE_SLEEP_SECONDS);
                final long sleepMillis = Math.round(boundedSeconds * 1000L) + ORACLE_TIMING_MARGIN_MILLIS;
                System.out.println(
                    "Oracle SQLi sleep requested=" + requestedSeconds + "s, actual=" + sleepMillis + "ms"
                );
                sleep(sleepMillis);
            } else if (name.contains("UTL_INADDR.get_host_name(")) {
                sleep(LEGACY_ORACLE_SLEEP_MILLIS);
            }
            return new ResponseEntity<>(result, HttpStatus.OK);
        }

        // XSLT Injection
        @ApiResponses(
            value = {
                @ApiResponse(
                    content = {
                        @Content(
                            mediaType = MediaType.TEXT_PLAIN_VALUE,
                            schema = @Schema(implementation = String.class)
                        )
                    }
                )
            }
        )
        @RequestMapping(value = "/vulnApp/xsltInjection", method = RequestMethod.GET)
        public ResponseEntity<String> xsltInjectionVuln(
            @RequestParam(value = "template") String template
        ) {
            if ("<".equals(template)) {
                return ResponseEntity.ok("XSLT compile error: SAXParseException");
            }
            if (template.contains("system-property('xsl:vendor')")) {
                return ResponseEntity.ok("Apache Xalan");
            }
            if (template.contains("runtime:getRuntime()")
                || template.contains("php:function('exec'")) {
                return ResponseEntity.ok("Cannot run program erroneous_command");
            }
            if (template.contains("document('http://")) {
                return ResponseEntity.ok("Connection Refused");
            }
            return ResponseEntity.ok("Transformation completed");
        }

        // Hidden File Found
        @Hidden
        @RequestMapping(
            value = {"/CVS/root", "/vulnApp/CVS/root"},
            method = RequestMethod.GET
        )
        public ResponseEntity<String> hiddenCvsRoot() {
            return ResponseEntity.ok()
                .contentType(MediaType.TEXT_PLAIN)
                .body(":pserver:build-user@source.internal:/srv/vuln-app");
        }

        // SQL Injection - PostgreSQL - Time Based
        // Cross Site Scripting (DOM Based)
        @ApiResponses(
            value = {
                @ApiResponse(
                    content = {
                        @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class)
                        )
                    }
                )
            }
        )
        @RequestMapping(value = "/vulnApp/sqlInjectionPostgres", method = RequestMethod.GET)
        public ResponseEntity<String> sqlInjectionPostgresVuln(
            @RequestParam(value = "name") String name
        )  {
            var result = "<html><body></body></html>";
            if (name == null) {
                return new ResponseEntity<>(result, HttpStatus.OK);
            }
            if (name.contains("pg_sleep(")) {
                payloadSent.add(name);
            }
            final Matcher match = SLEEP_PATTERN.matcher(name);
            if (!match.find()) {
                return new ResponseEntity<>(name, HttpStatus.OK);
            }
            try {
                final long sleepInput = Long.parseLong(match.group(1)) * 1000L;
                Thread.sleep(sleepInput);
            } catch (InterruptedException e) {
                // Ignore
            }
            return new ResponseEntity<>(result, HttpStatus.OK);
        }

        // SQL Injection - SQLite
        @ApiResponses(
            value = {
                @ApiResponse(
                    content = {
                        @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = Response.class)
                        )
                    }
                )
            }
        )
        @RequestMapping(value = "/vulnApp/sqlInjectionSqLite", method = RequestMethod.GET)
        public ResponseEntity<Response> sqlInjectionSQLiteVuln(
            @RequestParam(value = "name") String name
        )  {
            final var result = new Response();
            result.test = "<html><body></body></html>";
            if (name == null) {
                return new ResponseEntity<>(result, HttpStatus.OK);
            }
            System.out.println("SQLite SQLi param name = " + name);
            final Matcher randomblob = SQLITE_RANDOMBLOB_PATTERN.matcher(name);
            if (randomblob.find()) {
                final long blobBytes = Long.parseLong(randomblob.group(1));
                final long sleepMillis = sqliteRandomblobDelayMillis(blobBytes);
                System.out.println(
                    "SQLite SQLi randomblob bytes=" + blobBytes + ", sleep=" + sleepMillis + "ms"
                );
                sleep(sleepMillis);
            }
            return new ResponseEntity<>(result, HttpStatus.OK);
        }

        @Hidden
        @RequestMapping(value = "/clearData", method = RequestMethod.GET)
        public void clearData()  {
            commentRepository.clear();
            eventRepository.clear();
            payloadSent.clear();
            issueRepository.clear();
        }

        private void sleep(long sleepMillis) {
            try {
                Thread.sleep(sleepMillis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        private long sqliteRandomblobDelayMillis(long blobBytes) {
            if (blobBytes < SQLITE_MIN_RANDOMBLOB_BYTES) {
                return 0L;
            }
            /*
             * ZAP try this:
             * randomblob(100000)
             * randomblob(1000000)
             * randomblob(10000000)
             * We need to increase waiting time, but not over 10 seconds,
             * because ZAP restrict SQLite timing check ~ 10 seconds.
             */
            final double ratio = (double) blobBytes / SQLITE_MIN_RANDOMBLOB_BYTES;
            final double step = Math.max(1.0, Math.log10(ratio) + 1.0);
            final long delayMillis = Math.round(step * 900L);
            return Math.min(delayMillis, SQLITE_MAX_SLEEP_MILLIS);
        }
    }
}
