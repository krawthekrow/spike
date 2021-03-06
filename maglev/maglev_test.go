package maglev

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sipb/spike/common"
)

func TestTableSize(t *testing.T) {
	New(1e9 + 7) // a prime
	New(1e9 + 9) // its twin
	New(SmallM)
	New(BigM)
	assert.Panics(t, func() { New(1 << 60) }, "2^60 is not prime but table created")
	assert.Panics(t, func() { New(57) }, "57 is not prime but table created")
}

func TestAddAndRemove(t *testing.T) {
	backends := make([]common.Backend, 6)
	for i := 0; i < len(backends); i++ {
		backends[i] = common.Backend{IP: []byte{0, 0, 0, byte(i)}}
	}

	table := New(SmallM)

	table.Add(&backends[0])
	table.Add(&backends[1])
	table.Add(&backends[2])

	table.SetWeight(&backends[3], 2)
	table.SetWeight(&backends[3], 3)

	// Remove backend via remove
	table.Add(&backends[4])
	table.Remove(&backends[4])

	// Remove backend via setting weight to 0
	table.Add(&backends[5])
	table.SetWeight(&backends[5], 0)

	rand.Seed(42)
	freq := make(map[*common.Backend]uint)
	for i := 0; i < 1e4; i++ {
		cur, ok := table.Lookup(rand.Uint64())
		require.True(t, ok, "lookup failed")
		freq[cur]++
	}

	assert.Equal(t, 4, len(freq), "There should be 4 backends.")
	for i := 0; i < 4; i++ {
		assert.True(t, freq[&backends[i]] > 0, "backends[%d] not hit", i)
	}
}

func TestAddPanic(t *testing.T) {
	table := New(SmallM)
	assert.Panics(t, func() { table.Add(nil) }, "Add should panic on nil")
	assert.Panics(t, func() { table.SetWeight(nil, 2) }, "SetWeight should panic on nil")
}
func TestEmptyLookupPanic(t *testing.T) {
	table := New(SmallM)
	ret, backends := table.Lookup(100)
	assert.False(t, backends, "Did not report that there were no backends")
	assert.Nil(t, ret, "Did not return nil with no backends added")

	backend := common.Backend{IP: []byte{0, 0, 0, 0}}
	table.Add(&backend)
	table.SetWeight(&backend, 0)
	ret, backends = table.Lookup(100)
	assert.False(t, backends, "Did not report that there were no backends")
	assert.Nil(t, ret, "Did not return nil with no backends added")
}

func TestReconfig(t *testing.T) {
	backends := make([]common.Backend, 4)
	for i := 0; i < len(backends); i++ {
		backends[i] = common.Backend{IP: []byte{0, 0, 0, byte(i)}}
	}

	config := make(Config)
	for i := 0; i < len(backends); i++ {
		config[&backends[i]] = uint(i)
	}

	table := New(SmallM)
	table.Reconfig(config)

	rand.Seed(42)
	freq := make(map[*common.Backend]uint)
	for i := 0; i < 1e4; i++ {
		cur, ok := table.Lookup(rand.Uint64())
		require.True(t, ok, "lookup failed")
		freq[cur]++
	}

	assert.Equal(t, len(backends)-1, len(freq), "There should be %d backends.", len(backends)-1)
	assert.Zero(t, freq[&backends[0]], "backends[0] was hit")
	for i := 1; i < 4; i++ {
		assert.NotZero(t, freq[&backends[i]], "backends[%d] not hit", i)
	}
}

func TestReconfigPanic(t *testing.T) {
	backends := make([]common.Backend, 4)
	for i := 0; i < len(backends); i++ {
		backends[i] = common.Backend{IP: []byte{0, 0, 0, byte(i)}}
	}

	badConfig := make(Config)
	for i := 0; i < len(backends); i++ {
		badConfig[&backends[i]] = uint(i)
	}
	badConfig[nil] = 1

	table := New(SmallM)
	assert.Panics(t, func() { table.Reconfig(badConfig) }, "Reconfig should panic for nil entries in config")
}

func abs(n int64) int64 {
	if n < 0 {
		return -1 * n
	}
	return n
}

func TestDistribution(t *testing.T) {
	backends := make([]common.Backend, 50)
	for i := 0; i < len(backends); i++ {
		backends[i] = common.Backend{IP: []byte{0, 0, 0, byte(i)}}
	}

	tableSize := int64(1e6 + 3)
	totalWeight := int64(0)
	config := make(Config)
	for i := 0; i < len(backends); i++ {
		weight := uint(1 + i/5)
		config[&backends[i]] = weight
		totalWeight += int64(weight)
	}

	/*
		We will check that the lookup table matches the above config
		distribution reasonably well.
		More specifically, we check to see if the number of occurrences of
		each backend is within 10% of its expected value.
		An upper bound that the probability that this test fails assuming
		that each entry in the table is assigned randomly is 2.73e-4.
		How this bound was arrived at is shown below:

		By a Chernoff bound, the probability that we see more than 110% of
		an occurrence is at most

		    exp(-0.1^2 * backendWeight * tableSize / totalWeight / 3)

		Another Chernoff bound tells us the probability we see less than 90%
		of an occurrence is at most

		    exp(-0.1^2 * backendWeight * tableSize / totalWeight / 2)

		When tableSize = 1e6 + 3 and totalWeight = 275 (and conservatively
		setting backendWeight = 1 for all backends),
		a union bound across both tails and all backends gives a failure
		probability of at most 2.73e-4.
	*/

	table := New(uint64(tableSize))
	table.Reconfig(config)

	freq := make(map[*common.Backend]int64)
	for i := 0; i < len(table.lookup); i++ {
		freq[table.lookup[i]]++
	}

	assert.Equal(t, len(backends), len(freq), "There should be %d backends.", len(backends))
	for i := 0; i < len(backends); i++ {
		weight := int64(1 + i/5)
		occ := freq[&backends[i]]

		assert.InEpsilon(t, tableSize*weight, totalWeight*occ, 0.1,
			"Number of occurrences of backend %d is outside tolerance of 10%%.", i)
	}
}
