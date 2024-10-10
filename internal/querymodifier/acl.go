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

// ACL stores a role definition
type ACL struct {
	Fullaccess bool
	Metrics    map[string]metricsql.LabelFilter `json:"metrics"`
	RawACL     string
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
		Metrics: make(map[string]metricsql.LabelFilter),
		RawACL:  rawACL,
	}

	for label, value := range aclDef.Metrics {
		lf := metricsql.LabelFilter{
			Label:      label,
			Value:      value,
			IsRegexp:   strings.ContainsAny(value, RegexpSymbols),
			IsNegative: false,
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
	}

	acl.Fullaccess = isFullAccess(acl.Metrics)

	return acl, nil
}

// isFullAccess checks if the ACL grants full access
func isFullAccess(metrics map[string]metricsql.LabelFilter) bool {
	for _, lf := range metrics {
		if lf.Value == ".*" {
			return true
		}
	}
	return false
}

// ToLabelFilters converts the ACL's metrics to metricsql.LabelFilter slice
func (acl ACL) ToLabelFilters() []metricsql.LabelFilter {
	filters := make([]metricsql.LabelFilter, 0, len(acl.Metrics))
	for _, lf := range acl.Metrics {
		filters = append(filters, lf)
	}
	return filters
}
