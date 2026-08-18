package org.example.vulnApp.controller;

import static org.example.vulnApp.support.ZapAlertVulnSupport.escapeXml;
import static org.example.vulnApp.support.ZapAlertVulnSupport.safeLower;
import static org.example.vulnApp.support.ZapAlertVulnSupport.text;
import static org.example.vulnApp.support.ZapAlertVulnSupport.xml;

import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** XML-family alerts: XPath, XXE, and XSLT injection. */
@RestController
public class XmlInjectionAlertsController {

    @RequestMapping(value = "/vulnApp/xpathInjection", method = RequestMethod.GET)
    public ResponseEntity<String> xpathInjection(@RequestParam("name") String name) {
        String lower = safeLower(name);
        if (lower.contains(" or ") || lower.contains("'1'='1") || lower.contains("\"1\"=\"1")) {
            return xml("<users><user>admin</user><user>guest</user><user>zap</user></users>");
        }
        if (name.contains("'") || name.contains("\"")) {
            return xml("<error>XPathExpressionException: invalid predicate near " + escapeXml(name) + "</error>");
        }
        return xml("<users><user>" + escapeXml(name) + "</user></users>");
    }

    @RequestMapping(value = "/vulnApp/xxe", method = RequestMethod.POST, consumes = {MediaType.APPLICATION_XML_VALUE, MediaType.TEXT_XML_VALUE, MediaType.ALL_VALUE})
    public ResponseEntity<String> xxe(@RequestBody String body) {
        String lower = safeLower(body);
        if (lower.contains("<!entity") || lower.contains("system \"file:///") || lower.contains("system 'file:///")) {
            return text("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin");
        }
        return xml("<ok>true</ok>");
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
    public ResponseEntity<String> xsltInjection(@RequestParam(value = "template") String template) {
        if ("<".equals(template)) {
            return ResponseEntity.ok("XSLT compile error: SAXParseException");
        }
        if (template.contains("system-property('xsl:vendor')")) {
            return ResponseEntity.ok("Apache Xalan");
        }
        if (template.contains("runtime:getRuntime()") || template.contains("php:function('exec'")) {
            return ResponseEntity.ok("Cannot run program erroneous_command");
        }
        if (template.contains("document('http://")) {
            return ResponseEntity.ok("Connection Refused");
        }
        return ResponseEntity.ok("Transformation completed");
    }
}
