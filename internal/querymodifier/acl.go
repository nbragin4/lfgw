package querymodifier

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/VictoriaMetrics/metricsql"
	"gopkg.in/yaml.v3"
)

// RegexpSymbols is used to determine whether ACL definition is a regexp or whether LF contains a fake regexp
const RegexpSymbols = `.+*?^$()[]{}|\`

type LabelFilterData struct {
	Fullaccess bool
	RawACL     string
}

// ACL stores a role definition
type ACL struct {
	// Fullaccess  bool
	Metrics     map[string]metricsql.LabelFilter `json:"metrics"`
	MetricsMeta map[string]LabelFilterData
	// RawACL      string
}

// NewACL returns an ACL based on a YAML definition
func NewACL(rawACL string) (ACL, error) {
	var aclDef struct {
		Metrics map[string]string `yaml:"metrics"`
	}

	err := yaml.Unmarshal([]byte(rawACL), &aclDef)
	if err != nil {
		return ACL{}, fmt.Errorf("failed to unmarshal ACL: %w", err)
	}

	acl := ACL{
		Metrics:     make(map[string]metricsql.LabelFilter),
		MetricsMeta: make(map[string]LabelFilterData),
	}

	for label, value := range aclDef.Metrics {
		buffer, err := toSlice(value)
		lf := metricsql.LabelFilter{
			Label:      label,
			Value:      value,
			IsRegexp:   strings.ContainsAny(value, RegexpSymbols),
			IsNegative: false,
		}

		if err != nil {
			return ACL{}, err
		}
		fullaccess := false
		// If .* is in the slice, then we can omit any other value
		for _, v := range buffer {
			// TODO: move to a helper?
			if v == ".*" {
				// Note: with this approach, we intentionally omit other values in the resulting ACL
				lf.Value = v
				fullaccess = true
			}
		}
		if fullaccess {
			acl.Metrics[label] = lf
			acl.MetricsMeta[label] = LabelFilterData{
				Fullaccess: isFullAccess(lf),
				RawACL:     lf.Value,
			}
			continue
		}
		if len(buffer) == 1 {
			// TODO: move to a helper?
			if strings.ContainsAny(buffer[0], RegexpSymbols) {
				lf.IsRegexp = true
				// Trim anchors as they're not needed for Prometheus, and not expected in the app.shouldBeModified function
				buffer[0] = strings.TrimLeft(buffer[0], "^")
				buffer[0] = strings.TrimLeft(buffer[0], "(")
				buffer[0] = strings.TrimRight(buffer[0], "$")
				buffer[0] = strings.TrimRight(buffer[0], ")")
			}
			lf.Value = buffer[0]
		} else {
			// "Regex matches are fully anchored. A match of env=~"foo" is treated as env=~"^foo$"." https://prometheus.io/docs/prometheus/latest/querying/basics/
			lf.Value = strings.Join(buffer, "|")
			lf.IsRegexp = true
		}

		if lf.IsRegexp {
			// Trim anchors as they're not needed for Prometheus
			lf.Value = strings.TrimPrefix(lf.Value, "^")
			lf.Value = strings.TrimPrefix(lf.Value, "(")
			lf.Value = strings.TrimSuffix(lf.Value, "$")
			lf.Value = strings.TrimSuffix(lf.Value, ")")

			_, err := regexp.Compile(lf.Value)
			if err != nil {
				return ACL{}, fmt.Errorf("invalid regex for label %s: %w", label, err)
			}
		}
		acl.Metrics[label] = lf
		acl.MetricsMeta[label] = LabelFilterData{
			Fullaccess: isFullAccess(lf),
			RawACL:     strings.Join(buffer, ","),
		}
	}

	return acl, nil
}

// isFullAccess checks if the ACL grants full access
func isFullAccess(lf metricsql.LabelFilter) bool {
	return lf.Value == ".*"
}

// ToLabelFilters converts the ACL's metrics to metricsql.LabelFilter slice
func (acl ACL) ToLabelFilters() []metricsql.LabelFilter {
	filters := make([]metricsql.LabelFilter, 0, len(acl.Metrics))
	for _, lf := range acl.Metrics {
		filters = append(filters, lf)
	}
	return filters
}
