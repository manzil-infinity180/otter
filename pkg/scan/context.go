package scan

import (
	"context"

	stereoscopeimage "github.com/anchore/stereoscope/pkg/image"
)

type registryOptionsKey struct{}
type platformKey struct{}

func ContextWithRegistryOptions(ctx context.Context, options *stereoscopeimage.RegistryOptions) context.Context {
	if options == nil {
		return ctx
	}
	return context.WithValue(ctx, registryOptionsKey{}, options)
}

func ContextWithPlatform(ctx context.Context, platform *stereoscopeimage.Platform) context.Context {
	if platform == nil {
		return ctx
	}
	return context.WithValue(ctx, platformKey{}, platform)
}

func RegistryOptionsFromContext(ctx context.Context) *stereoscopeimage.RegistryOptions {
	if ctx == nil {
		return nil
	}
	options, _ := ctx.Value(registryOptionsKey{}).(*stereoscopeimage.RegistryOptions)
	return options
}

func PlatformFromContext(ctx context.Context) *stereoscopeimage.Platform {
	if ctx == nil {
		return nil
	}
	platform, _ := ctx.Value(platformKey{}).(*stereoscopeimage.Platform)
	return platform
}
