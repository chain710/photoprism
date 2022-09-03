package thumb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSize_ExceedsLimit(t *testing.T) {
	SizePrecached = 1024
	SizeUncached = 2048

	fit4096 := Sizes[Fit4096]
	assert.True(t, fit4096.ExceedsLimit())

	fit2048 := Sizes[Fit2048]
	assert.False(t, fit2048.ExceedsLimit())

	tile500 := Sizes[Tile500]
	assert.False(t, tile500.ExceedsLimit())

	SizePrecached = 2048
	SizeUncached = 7680
}

func TestSize_Uncached(t *testing.T) {
	SizePrecached = 1024
	SizeUncached = 2048

	fit4096 := Sizes[Fit4096]
	assert.True(t, fit4096.Uncached())

	fit2048 := Sizes[Fit2048]
	assert.True(t, fit2048.Uncached())

	tile500 := Sizes[Tile500]
	assert.False(t, tile500.Uncached())

	SizePrecached = 2048
	SizeUncached = 7680
}

func TestResampleFilter_Imaging(t *testing.T) {
	t.Run("Blackman", func(t *testing.T) {
		r := ResampleBlackman.Imaging()
		assert.Equal(t, float64(3), r.Support)
	})
	t.Run("Cubic", func(t *testing.T) {
		r := ResampleCubic.Imaging()
		assert.Equal(t, float64(2), r.Support)
	})
	t.Run("Linear", func(t *testing.T) {
		r := ResampleLinear.Imaging()
		assert.Equal(t, float64(1), r.Support)
	})
}
