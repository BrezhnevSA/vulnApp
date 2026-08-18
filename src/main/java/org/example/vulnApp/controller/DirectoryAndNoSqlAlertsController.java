package org.example.vulnApp.controller;

import static org.example.vulnApp.support.ZapAlertVulnSupport.MONGO_WHERE_SLEEP_PATTERN;
import static org.example.vulnApp.support.ZapAlertVulnSupport.json;
import static org.example.vulnApp.support.ZapAlertVulnSupport.safeLower;
import static org.example.vulnApp.support.ZapAlertVulnSupport.sleepSecondsOrMillisWithMargin;
import static org.example.vulnApp.support.ZapAlertVulnSupport.text;

import java.util.regex.Matcher;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** LDAP and document-database reproductions. */
@RestController
public class DirectoryAndNoSqlAlertsController {

    @RequestMapping(value = "/vulnApp/ldapInjection", method = RequestMethod.GET)
    public ResponseEntity<String> ldapInjection(@RequestParam("user") String user) {
        String lower = safeLower(user);
        if (lower.contains("*") || lower.contains(")(") || lower.contains("|") || lower.contains("&")) {
            return text("LDAP result: uid=admin,ou=people,dc=example,dc=org\nuid=guest,ou=people,dc=example,dc=org");
        }
        if (user.contains("(") || user.contains(")")) {
            return text("javax.naming.InvalidSearchFilterException: Unbalanced parenthesis");
        }
        return text("LDAP result: uid=" + user);
    }

    @RequestMapping(value = "/vulnApp/noSqlInjectionMongo", method = RequestMethod.GET)
    public ResponseEntity<String> noSqlInjectionMongo(@RequestParam("filter") String filter) {
        String lower = safeLower(filter);
        if (lower.contains("$ne") || lower.contains("$where") || lower.contains("true")) {
            Matcher m = MONGO_WHERE_SLEEP_PATTERN.matcher(filter);
            if (m.find()) {
                sleepSecondsOrMillisWithMargin(Double.parseDouble(m.group(1)));
            }
            return json("{\"users\":[\"admin\",\"guest\",\"zap\"]}");
        }
        return json("{\"users\":[\"" + filter.replace("\"", "'") + "\"]}");
    }
}
