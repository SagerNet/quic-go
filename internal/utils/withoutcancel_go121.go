//go:build go1.21

package utils

import (
	"context"
)

var WithoutCancel = context.WithoutCancel
