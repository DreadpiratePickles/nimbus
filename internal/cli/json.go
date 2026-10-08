package cli

import (
	"context"
	"encoding/json"
)

func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }
func contextBackground() context.Context     { return context.Background() }
