package querymodifier

import (
	"testing"

	"github.com/VictoriaMetrics/metricsql"
	"github.com/stretchr/testify/assert"
)

func Test_NewACL(t *testing.T) {
	tests := []struct {
		name   string
		rawACL string
		want   ACL
		fail   bool
	}{
		{
			name:   ".* (full access)",
			rawACL: "metrics: { namespace: '.*' }",
			want: ACL{
				Metrics: map[string]metricsql.LabelFilter{
					"namespace": {
						Label:      "namespace",
						Value:      ".*",
						IsRegexp:   true,
						IsNegative: false,
					},
				},
				MetricsMeta: map[string]LabelFilterData{
					"namespace": {
						Fullaccess: true,
						RawACL:     ".*",
					},
				},
			},
			fail: false,
		},
		{
			name:   "min.*, .*, stolon (implicit full access, same as .*)",
			rawACL: "metrics: { namespace: 'min.*, .*, stolon' }",
			want: ACL{
				Metrics: map[string]metricsql.LabelFilter{
					"namespace": {
						Label:      "namespace",
						Value:      ".*",
						IsRegexp:   true,
						IsNegative: false,
					},
				},
				MetricsMeta: map[string]LabelFilterData{
					"namespace": {
						Fullaccess: true,
						RawACL:     ".*",
					},
				},
			},
			fail: false,
		},
		{
			name:   "minio (only minio)",
			rawACL: "metrics: { namespace: 'minio' }",
			want: ACL{
				Metrics: map[string]metricsql.LabelFilter{
					"namespace": {
						Label:      "namespace",
						Value:      "minio",
						IsRegexp:   false,
						IsNegative: false,
					}},
				MetricsMeta: map[string]LabelFilterData{
					"namespace": {
						Fullaccess: false,
						RawACL:     "minio",
					},
				},
			},
			fail: false,
		},
		{
			name:   "min.* (one regexp)",
			rawACL: "metrics: { namespace: 'min.*' }",
			want: ACL{
				Metrics: map[string]metricsql.LabelFilter{
					"namespace": {
						Label:      "namespace",
						Value:      "min.*",
						IsRegexp:   true,
						IsNegative: false,
					},
				},
				MetricsMeta: map[string]LabelFilterData{
					"namespace": {
						Fullaccess: false,
						RawACL:     "min.*",
					},
				},
			},
			fail: false,
		},
		{
			name:   "min.* (one anchored regexp)",
			rawACL: "metrics: { namespace: '^(min.*)$' }",
			want: ACL{
				Metrics: map[string]metricsql.LabelFilter{
					"namespace": {
						Label:      "namespace",
						Value:      "min.*",
						IsRegexp:   true,
						IsNegative: false,
					}},
				MetricsMeta: map[string]LabelFilterData{
					"namespace": {
						Fullaccess: false,
						RawACL:     "min.*",
					},
				},
			},
			fail: false,
		},
		{
			name:   "minio, stolon (two namespaces)",
			rawACL: "metrics: { namespace: 'minio, stolon' }",
			want: ACL{
				Metrics: map[string]metricsql.LabelFilter{
					"namespace": {
						Label:      "namespace",
						Value:      "minio|stolon",
						IsRegexp:   true,
						IsNegative: false,
					},
				},
				MetricsMeta: map[string]LabelFilterData{
					"namespace": {
						Fullaccess: false,
						RawACL:     "minio,stolon",
					},
				},
			},
			fail: false,
		},
		{
			name:   "min.*, stolon (regexp and non-regexp)",
			rawACL: "metrics: { namespace: 'min.*, stolon' }",
			want: ACL{
				Metrics: map[string]metricsql.LabelFilter{
					"namespace": {
						Label:      "namespace",
						Value:      "min.*|stolon",
						IsRegexp:   true,
						IsNegative: false,
					}},
				MetricsMeta: map[string]LabelFilterData{
					"namespace": {
						Fullaccess: false,
						RawACL:     "min.*,stolon",
					},
				},
			},
			fail: false,
		},
		// TODO: assign special meaning to this regexp?
		{
			name:   ".+ (is a regexp)",
			rawACL: "metrics: { namespace: '.+' }",
			want: ACL{
				Metrics: map[string]metricsql.LabelFilter{
					"namespace": {
						Label:      "namespace",
						Value:      ".+",
						IsRegexp:   true,
						IsNegative: false,
					},
				},
				MetricsMeta: map[string]LabelFilterData{
					"namespace": {
						Fullaccess: false,
						RawACL:     ".+",
					},
				},
			},
			fail: false,
		},
		{
			name:   "a,b (is a correct regexp)",
			rawACL: "metrics: { namespace: 'a,b' }",
			want: ACL{
				Metrics: map[string]metricsql.LabelFilter{
					"namespace": {
						Label:      "namespace",
						Value:      "a|b",
						IsRegexp:   true,
						IsNegative: false,
					},
				},
				MetricsMeta: map[string]LabelFilterData{
					"namespace": {
						Fullaccess: false,
						RawACL:     "a,b",
					},
				},
			},
			fail: false,
		},
		{
			name:   "[ (incorrect regexp)",
			rawACL: "metrics: { namespace: '[' }",
			want:   ACL{},
			fail:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewACL(tt.rawACL)
			if tt.fail {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
