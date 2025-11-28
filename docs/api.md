
```
## Events
app.otterxf.com/api/analytics/events

```

```
POST:
/api/v1/scans

## payloads 
{
    arch: "amd64" // arm64
    creds_id: "unique_id" // for private repo ig
    "image_name": "container-image"
    "registry": "https://index.docker.io/v1"
}
```

```
GET: /api/v1/scans/<id>
```

```
GET: /api/v1/releases/bundles

"id"': "rb_5360c2b0e99e40b4b9f346c584fcd63c",
"created_at": "2025-11-09T19:34:23.4272",
"updated_at":
"2025-11-09T19:34:23.4272",
"organization_id": "org_c465b6e9da2c40eebfb079ffca63331c",
"name": "scn_c5b68937d30a46fcbe2129981f959a90_rootio"

GET: /api/v1/scans/scn_c5b68937d30a46fcbe2129981f959a90_rootio


GET /api/v1/orgs/org_c465b6e9da2c40eebfb079ffca63331c/inventory/image_builds

{
    "id": "imgb_31b12a40ef9b48f488473d2dcb51c68c"
    "tag": "latest"
    "repository": "manzilrahul/k8s-custom-controller",
    "digest": "sha256:e27666672827fd428fc38848c2e6d48513e117b2"
    "oci_image_id": "sha256:3745412fcb095f225072bcda7e043adbal"
    "scanned_at": "2025-11-09T19:32:37.453Z"
    "arch": "arm64",
    "ecosystem": "alpine",
    "os_distro_release": "3.20.7"
}

GET: /api/artifacts/vex/scn_8972d44e1af142ef9b4a808f72f884d8
GET: /api/artifacts/sbom/scn_8972d44e1af142ef9b4a808f72f884d8
GET: /api/artifacts/provenance/scn_8972d44e1af142ef9b4a808f72f884d8
{
    "provenance_file_url": "https://s3.us-east-1.amazonaws.com/rootio-prod-avr-metadata/org_c46
    5b6e9da2c40eebfb079ffca63331c/imgrmd_4ab45e9097634f90b2e35
    0790532e24f/provenance.json?X-Amz-Algorithm=AWS4-HMAC-SHA25
    6&X-Amz-Credential=ASIA5FTZFQ7EPHQ74PNU%2F20251123%2Fus-e ast-1%2Fs3%2Faws4_request&X-Amz-Date=20251123T103540Z&X-A mz-Expires=7200&X-Amz-Security-Token=lQoJb3JpZ2luX2VjEHMaCXV"

}
```
