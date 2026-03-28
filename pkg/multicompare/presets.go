package multicompare

// Presets returns the built-in comparison templates.
func Presets() []PresetComparison {
	return []PresetComparison{
		{
			ID:          "nginx-3way",
			Name:        "Nginx: 3-Way Battle",
			Description: "Compare Docker Official, Chainguard, and Bitnami Nginx images",
			Images: []ImageTarget{
				{Name: "nginx:latest"},
				{Name: "cgr.dev/chainguard/nginx:latest"},
				{Name: "bitnami/nginx:latest"},
			},
		},
		{
			ID:          "go-official-vs-chainguard",
			Name:        "Go: Official vs Chainguard",
			Description: "Compare Docker Official Go image with Chainguard hardened variant",
			Images: []ImageTarget{
				{Name: "golang:latest"},
				{Name: "cgr.dev/chainguard/go:latest"},
			},
		},
		{
			ID:          "python-slim-vs-chainguard",
			Name:        "Python: Slim vs Chainguard",
			Description: "Compare Python slim with Chainguard hardened Python",
			Images: []ImageTarget{
				{Name: "python:3.12-slim"},
				{Name: "cgr.dev/chainguard/python:latest"},
			},
		},
		{
			ID:          "node-alpine-vs-chainguard",
			Name:        "Node: Alpine vs Chainguard",
			Description: "Compare Node.js Alpine with Chainguard hardened Node.js",
			Images: []ImageTarget{
				{Name: "node:22-alpine"},
				{Name: "cgr.dev/chainguard/node:latest"},
			},
		},
		{
			ID:          "alpine-vs-wolfi",
			Name:        "Alpine vs Wolfi",
			Description: "Compare minimal base images: Alpine vs Chainguard Wolfi",
			Images: []ImageTarget{
				{Name: "alpine:latest"},
				{Name: "cgr.dev/chainguard/wolfi-base:latest"},
			},
		},
		{
			ID:          "redis-3way",
			Name:        "Redis: 3-Way Battle",
			Description: "Compare Docker Official, Chainguard, and Bitnami Redis images",
			Images: []ImageTarget{
				{Name: "redis:latest"},
				{Name: "cgr.dev/chainguard/redis:latest"},
				{Name: "bitnami/redis:latest"},
			},
		},
		{
			ID:          "postgres-official-vs-bitnami",
			Name:        "PostgreSQL: Official vs Bitnami",
			Description: "Compare Docker Official PostgreSQL with Bitnami variant",
			Images: []ImageTarget{
				{Name: "postgres:16"},
				{Name: "bitnami/postgresql:16"},
			},
		},
	}
}
