package global

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnmarshalExample(t *testing.T) {
	data, err := os.ReadFile("../../../examples/global_GHSA/GHSA-cpj6-fhp6-mr6j.json")
	assert.NoError(t, err)

	var adv Advisory
	err = json.Unmarshal(data, &adv)
	assert.NoError(t, err)

	// Verify some fields to see if they are correctly unmarshaled
	assert.Equal(t, "GHSA-cpj6-fhp6-mr6j", adv.ID)

	// Identifiers
	assert.Len(t, adv.Identifiers, 2)
	assert.Equal(t, "GHSA", adv.Identifiers[0].Type)
	assert.Equal(t, "GHSA-cpj6-fhp6-mr6j", adv.Identifiers[0].Value)

	// CVSS Severities
	assert.NotNil(t, adv.CVSSSeverities)
	assert.NotNil(t, adv.CVSSSeverities.CVSSv3)
	assert.Equal(t, 8.2, *adv.CVSSSeverities.CVSSv3.Score)
	assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H", *adv.CVSSSeverities.CVSSv3.VectorString)
	assert.NotNil(t, adv.CVSSSeverities.CVSSv4)
	assert.Equal(t, 0.0, *adv.CVSSSeverities.CVSSv4.Score)
	assert.Nil(t, adv.CVSSSeverities.CVSSv4.VectorString)

	// EPSS
	assert.NotNil(t, adv.EPSS)
	assert.Equal(t, 0.00797, *adv.EPSS.Percentage)

	// User fields in credits
	assert.NotEmpty(t, adv.Credits)
	assert.Equal(t, "cold-try", adv.Credits[0].User.Login)
	assert.Equal(t, int64(54223593), adv.Credits[0].User.ID)

	// Dates
	assert.False(t, adv.PublishedAt.IsZero())
	assert.NotNil(t, adv.GithubReviewedAt)
	assert.False(t, adv.GithubReviewedAt.IsZero())
	assert.Nil(t, adv.WithdrawnAt)
}
