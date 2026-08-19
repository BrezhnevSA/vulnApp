package org.example.vulnApp.controller;

import io.swagger.v3.oas.annotations.Hidden;
import org.example.vulnApp.state.VulnAppState;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/** Non-vulnerability utility endpoints for navigation and test-state reset. */
@RestController
public class AppUtilityController {
    private final VulnAppState state;

    public AppUtilityController(VulnAppState state) {
        this.state = state;
    }

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
                    + "<a href='vulnApp/sqlInjectionOracleTimeBased?name=test'>Oracle query</a>"
                    + "<a href='vulnApp/sqlInjectionHypersonicTimeBased?name=test'>Hypersonic query</a>"
                    + "<a href='vulnApp/xpathInjection?name=test'>XPath query</a>"
                    + "<a href='vulnApp/serverSideTemplateInjection?template=template'>SSTI query</a>"
                    + "<a href='vulnApp/expressionLanguageInjection?expr=value'>EL query</a>"
                    + "<a href='vulnApp/noSqlInjectionMongo?filter=filter'>Mongo query</a>"
                    + "<a href='vulnApp/ssrf?url=http://example.org/'>SSRF query</a>"
                    + "<a href='vulnApp/parameterTampering?price=10'>Parameter tampering query</a>"
                    + "<a href='vulnApp/bufferOverflow?input=abc'>Buffer query</a>"
                    + "<a href='vulnApp/paddingOracle?token=ffffffffffffffffffffffffffffff10'>Padding oracle query</a>"
                    + "<a href='.env'>Env file</a>"
                    + "<a href='elmah.axd'>ELMAH</a>"
                    + "<a href='WEB-INF/web.xml'>WEB-INF</a>"
                    + "<a href='actuator/health'>Actuator health</a>"
                    + "<a href='vulnApp/xsltInjection?template=text'>XSLT transform</a>"
                    + "</body></html>"
            );
    }

    @Hidden
    @RequestMapping(value = "/clearData", method = RequestMethod.GET)
    public ResponseEntity<Void> clearData() {
        state.clear();
        return ResponseEntity.ok().build();
    }
}
