package engine

import "context"

// dagMockModule is a test helper for DAG schema tests.
// This is a minimal mock that implements the Module interface.
type dagMockModule struct {
	meta ModuleMetadata
}

func (m *dagMockModule) Metadata() ModuleMetadata {
	return m.meta
}

func (m *dagMockModule) Init(instanceID string, moduleConfig map[string]any) error {
	return nil
}

func (m *dagMockModule) Execute(ctx context.Context, inputs map[string]any, outputChan chan<- ModuleOutput) error {
	return nil
}
