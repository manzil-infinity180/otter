1. Run the trivy server `trivy server --listen 0.0.0.0:8080`
2. Scan the image `trivy image --server http://localhost:8080 nginx:latest `
3. Scan the image with the sbom output `trivy image --server http://localhost:8080 -f cyclonedx -o results.cdx.json nginx:latest`
4.  trivy sbom results.cdx.json
example: 
```json



```

```
// sbom to vulnerability (json)
grype -o json sbom:go-cyclonedx.json > hello.json 
```