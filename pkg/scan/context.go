package scan

import (
	"context"

	stereoscopeimage "github.com/anchore/stereoscope/pkg/image"
)

type registryOptionsKey struct{}

func ContextWithRegistryOptions(ctx context.Context, options *stereoscopeimage.RegistryOptions) context.Context {
	if options == nil {
		return ctx
	}
	return context.WithValue(ctx, registryOptionsKey{}, options)
}

func RegistryOptionsFromContext(ctx context.Context) *stereoscopeimage.RegistryOptions {
	if ctx == nil {
		return nil
	}
	options, _ := ctx.Value(registryOptionsKey{}).(*stereoscopeimage.RegistryOptions)
	return options
}
