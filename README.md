# Vulnerable app for owasp/zap testing

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

### Already built image in root - `image.tar`

### OpenAPI

http://localhost:8090/app/v3/api-docs

http://localhost:8090/app/swagger-ui/index.html


