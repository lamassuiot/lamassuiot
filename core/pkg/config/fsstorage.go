package config

type FSStorageProvider string

const (
	LocalFilesystem FSStorageProvider = "local"
	AWSS3           FSStorageProvider = "s3"
)

type FSStorageConfig struct {
	ID       string                 `mapstructure:"id"`
	Metadata map[string]interface{} `mapstructure:"metadata"`
	Type     FSStorageProvider      `mapstructure:"type"`
	Config   map[string]interface{} `mapstructure:",remain"`
}

type FSStorageConfigAdapter[E any] struct {
	ID       string
	Metadata map[string]interface{}
	Type     FSStorageProvider
	Config   E
}

func (c FSStorageConfigAdapter[E]) Marshal(ce FSStorageConfig) (*FSStorageConfigAdapter[E], error) {
	config, err := DecodeStruct[E](ce.Config)
	if err != nil {
		return nil, err
	}
	return &FSStorageConfigAdapter[E]{
		ID:       ce.ID,
		Metadata: ce.Metadata,
		Type:     ce.Type,
		Config:   config,
	}, nil
}

func (c FSStorageConfigAdapter[E]) Unmarshal() (*FSStorageConfig, error) {

	config, err := EncodeStruct(c.Config)
	if err != nil {
		return nil, err
	}

	return &FSStorageConfig{
		ID:       c.ID,
		Metadata: c.Metadata,
		Type:     c.Type,
		Config:   config,
	}, nil
}
