# Vulnerable app for owasp/zap testing

This app mocks some of the alerts from the owasp\zap tool. Use it to test your owasp\zap instance.

Mocked alerts (!!! - temporary not found by scan, in dev):

### SQL

| ID / AlertRef | Alert name | Where catch |
|---|---|---|
|40018 |	SQL Injection |	/vulnApp/sqlInjectionGeneric |
|40019 |	SQL Injection - MySQL (Time Based) |	/vulnApp/sqlInjectionMySqlTimeBased |
|40020 | !!!	SQL Injection - Hypersonic SQL (Time Based) |	/vulnApp/sqlInjectionHypersonicTimeBased |
|40021 |	SQL Injection - Oracle (Time Based) |	/vulnApp/sqlInjectionOracleTimeBased |
|40022 |	SQL Injection - PostgreSQL (Time Based) |	/vulnApp/sqlInjectionPostgres |
|40027 |	SQL Injection - MsSQL (Time Based) |	/vulnApp/sqlInjectionMsSqlTimeBased |
|40024 |	SQL Injection - SQLite (Time Based) |	/vulnApp/sqlInjectionSqLite /vulnApp/sqlInjectionSqLiteTimeBased /vulnApp/sqlInjectionSqLiteError |

### XSS

| ID / AlertRef | Alert name | Where catch |
|---|---|---|
|40012 | Cross Site Scripting (Reflected) |	/vulnApp/cssw/html |
|40012 | Cross Site Scripting Weakness (Reflected in JSON Response) |	/vulnApp/cssw |
|40014 | Cross Site Scripting (Persistent) |	/event |
|40014-2 | Cross Site Scripting Weakness (Persistent in JSON Response) |	/comment |

### XML / XPath / XSLT


| ID / AlertRef | Alert name | Where catch |
|---|---|---|
|90017 |	XSLT Injection |	/vulnApp/xsltInjection |
|90021 |	!!! XPath Injection |	/vulnApp/xpathInjection |
|90023 |	!!! XML External Entity Attack |	/vulnApp/xxe |

### Code execution / template / command injection


| ID / AlertRef | Alert name | Where catch |
|---|---|---|
|90019-1 |	!!! Server Side Code Injection - PHP Code Injection |	/vulnApp/serverSideCodeInjection |
|90020 |	Remote OS Command Injection |	/vulnApp/osCommandInjection |
|90037 |	Remote OS Command Injection (Time Based) |	/vulnApp/osCommandInjectionTimeBased |
|90035 |	!!! Server Side Template Injection |	/vulnApp/serverSideTemplateInjection |
|90036 |	!!! Server Side Template Injection (Blind) |	/vulnApp/serverSideTemplateInjection |
|90025 |	!!! Expression Language Injection |	/vulnApp/expressionLanguageInjection |

### LDAP / NoSQL / SSRF-cloud


| ID / AlertRef | Alert name | Where catch |
|---|---|---|
|40015 |	LDAP Injection |	/vulnApp/ldapInjection |
|40033 |	!!! NoSQL Injection - MongoDB |	/vulnApp/noSqlInjectionMongo |
|90039 |	!!! NoSQL Injection - MongoDB (Time Based) |	/vulnApp/noSqlInjectionMongo |
|90034 |	!!! Cloud Metadata Potentially Exposed |	/vulnApp/ssrf |

### Web misconfiguration / active checks


| ID / AlertRef | Alert name | Where catch |
|---|---|---|
|20019-1 / 20019-2 |	External Redirect |	/vulnApp/externalRedirect |
|40040-* |	!!! CORS Misconfiguration / CORS Header |	/vulnApp/cors |
|40008 |	!!! Parameter Tampering |	/vulnApp/parameterTampering |
|30001 |	!!! Buffer Overflow |	/vulnApp/bufferOverflow |
|30002 |	Format String Error |	/vulnApp/formatString |
|90024 |	!!! Generic Padding Oracle |	/vulnApp/paddingOracle |
|90028 |	!!! Insecure HTTP Method |	/vulnApp/insecureMethod |

### Resource disclosure / hidden files


| ID / AlertRef | Alert name | Where catch |
|---|---|---|
|40028 |	!!! ELMAH Information Leak |	/elmah.axd or /vulnApp/elmah.axd |
|40029 |	!!! Trace.axd Information Leak |	/trace.axd or /vulnApp/trace.axd |
|40032 |	.htaccess Information Leak |	/.htaccess or /vulnApp/.htaccess |
|40034 |	!!! .env Information Leak	/.env or | /vulnApp/.env |
|40035 |	Hidden File Found |	/.git/config, /CVS/root, mb /WEB-INF/web.xml |
|40042 |	!!! Spring Actuator Information Leak |	/actuator/env, /actuator/heapdump |
|10045 / 10045-2 |	!!! Source Code Disclosure - /WEB-INF folder / Properties File Disclosure  | /WEB-INF folder |

### Possible alerts 

| ID / AlertRef | Alert name |
|---|---|
|10020 |	Missing Anti-clickjacking Header |
|10021 |	X-Content-Type-Options Header Missing |
|10035 |	!!! Strict-Transport-Security Header Not Set |
|10038 |	Content Security Policy Header Not Set |
|10036 |	!!! Server Leaks Information via ... |
|10054 |	!!! Cookie without SameSite  |
|10096 |	!!! Timestamp Disclosure |
|40026 | Cross Site Scripting (DOM Based) |
|40043 | !!! Log4Shell	 |
|40045 | !!! Spring4Shell |
|40048 | !!! React2Shell	нет React Server Components endpoint |
|90026 | !!! SOAP Action Spoofing / 90029 SOAP XML Injection |
|50000 | !!! Script Active Scan Rules |

### **How to run locally:**

- Run in cmd:
```
mvn clean install
```

- Run in cmd:
```
docker build -f dockerfile/local.dockerfile -t vulnapp .
```

- Add to your compose with dast:

```
  vulnapp:
    image: vulnapp
    container_name: vulnapp
    ports:
      - 8090:8080
```

- for container with owasp/zap add next row:

```
  links:
    - vulnapp
```

- Go to http://localhost:8090/app/swagger-ui/index.html and download openapi file or get from root folder `openapi.json` file
- For start scan use url http://vulnapp:8080 and set openapi file
- After scan use GET /clearData for reset app for defaults

### OpenAPI

http://localhost:8090/app/v3/api-docs

http://localhost:8090/app/swagger-ui/index.html


