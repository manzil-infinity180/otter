package scan

import (
	"fmt"
	"sync"
)

// ScannerFactory creates a VulnerabilityScanner from configuration.
type ScannerFactory func(config map[string]string) (VulnerabilityScanner, error)

// ScannerRegistry manages scanner plugin registration and instantiation.
type ScannerRegistry struct {
	mu        sync.RWMutex
	factories map[string]ScannerFactory
}

// NewScannerRegistry creates an empty scanner registry.
func NewScannerRegistry() *ScannerRegistry {
	return &ScannerRegistry{
		factories: make(map[string]ScannerFactory),
	}
}

// Register adds a scanner factory under the given name.
func (r *ScannerRegistry) Register(name string, factory ScannerFactory) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.factories[name]; exists {
		return fmt.Errorf("scanner %q already registered", name)
	}
	r.factories[name] = factory
	return nil
}

// Create instantiates a scanner by name with the given configuration.
func (r *ScannerRegistry) Create(name string, config map[string]string) (VulnerabilityScanner, error) {
	r.mu.RLock()
	factory, ok := r.factories[name]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("scanner %q not registered; available: %v", name, r.Available())
	}
	return factory(config)
}

// Available returns the names of all registered scanners.
func (r *ScannerRegistry) Available() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	return names
}

// DefaultRegistry is the global scanner plugin registry.
var DefaultRegistry = NewScannerRegistry()
