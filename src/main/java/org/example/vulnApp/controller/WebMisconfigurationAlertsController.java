package org.example.vulnApp.controller;

import static org.example.vulnApp.support.ZapAlertVulnSupport.json;
import static org.example.vulnApp.support.ZapAlertVulnSupport.safeLower;
import static org.example.vulnApp.support.ZapAlertVulnSupport.text;

import java.net.URI;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Web misconfiguration and generic input-handling reproductions. */
@RestController
public class WebMisconfigurationAlertsController {

    @RequestMapping(value = "/vulnApp/externalRedirect", method = RequestMethod.GET)
    public ResponseEntity<Void> externalRedirect(@RequestParam("url") String url) {
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(url)).build();
    }

    @RequestMapping(value = "/vulnApp/cors", method = {RequestMethod.GET, RequestMethod.OPTIONS})
    public ResponseEntity<String> cors(@RequestHeader(value = "Origin", required = false) String origin) {
        String allowOrigin = origin == null ? "*" : origin;
        return ResponseEntity.ok()
            .header("Access-Control-Allow-Origin", allowOrigin)
            .header("Access-Control-Allow-Credentials", "true")
            .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            .header("Access-Control-Allow-Headers", "*")
            .body("cors-ok");
    }

    @RequestMapping(value = "/vulnApp/parameterTampering", method = RequestMethod.GET)
    public ResponseEntity<String> parameterTampering(@RequestParam("price") String price) {
        return json("{\"acceptedPrice\":" + price.replaceAll("[^0-9.-]", "") + ",\"status\":\"order-created\"}");
    }

    @RequestMapping(value = "/vulnApp/bufferOverflow", method = RequestMethod.GET)
    public ResponseEntity<String> bufferOverflow(@RequestParam("input") String input) {
        if (input.length() > 4096) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.TEXT_PLAIN)
                .body("Segmentation fault (core dumped)");
        }
        return text("ok");
    }

    @RequestMapping(value = "/vulnApp/formatString", method = RequestMethod.GET)
    public ResponseEntity<String> formatString(@RequestParam("input") String input) {
        if (input.contains("%x") || input.contains("%s") || input.contains("%n")) {
            return text("41414141 42424242 7ffeefbff5c0 " + input);
        }
        return text("ok");
    }

    @RequestMapping(value = "/vulnApp/ssrf", method = RequestMethod.GET)
    public ResponseEntity<String> ssrf(@RequestParam("url") String url) {
        String lower = safeLower(url);
        if (lower.contains("169.254.169.254") || lower.contains("metadata.google.internal") || lower.contains("metadata/instance")) {
            return json("{\"instanceId\":\"i-1234567890abcdef0\",\"iam\":\"admin-role\"}");
        }
        return text("fetched " + url);
    }

    @RequestMapping(value = "/vulnApp/paddingOracle", method = RequestMethod.GET)
    public ResponseEntity<String> paddingOracle(@RequestParam("token") String token) {
        if (token.length() % 2 == 1) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.TEXT_PLAIN)
                .body("javax.crypto.BadPaddingException: Given final block not properly padded");
        }
        return text("token accepted");
    }

    @RequestMapping(value = "/vulnApp/insecureMethod", method = {RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.TRACE})
    public ResponseEntity<String> insecureMethod() {
        return text("method accepted");
    }
}
