package querymodifier

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/VictoriaMetrics/metricsql"
)

// QueryModifier is used for modifying PromQL / MetricsQL requests. The exact changes are determined by an ACL and further tuned by deduplication and expression optimizations.
type QueryModifier struct {
	ACL                 ACL
	EnableDeduplication bool
	OptimizeExpressions bool
}

// GetModifiedEncodedURLValues rewrites GET/POST "query" and "match" parameters to filter out metrics.
func (qm *QueryModifier) GetModifiedEncodedURLValues(params url.Values) (string, error) {
	newParams := url.Values{}

	if len(qm.ACL.Metrics) == 0 {
		return "", fmt.Errorf("ACL cannot be empty")
	}

	for k, vv := range params {
		switch k {
		case "query", "match[]":
			for _, v := range vv {
				{
					expr, err := metricsql.Parse(v)
					if err != nil {
						return "", err
					}

					expr = qm.modifyMetricExpr(expr)
					if qm.OptimizeExpressions {
						expr = metricsql.Optimize(expr)
					}

					newVal := string(expr.AppendString(nil))
					newParams.Add(k, newVal)
				}
			}
		default:
			for _, v := range vv {
				newParams.Add(k, v)
			}
		}
	}

	return newParams.Encode(), nil
}

// modifyMetricExpr walks through the query and modifies only metricsql.Expr based on the supplied acl with label filters.
func (qm *QueryModifier) modifyMetricExpr(expr metricsql.Expr) metricsql.Expr {
	newExpr := metricsql.Clone(expr)

	modifyLabelFilter := func(expr metricsql.Expr) {
		if me, ok := expr.(*metricsql.MetricExpr); ok {
			for label, lf := range qm.ACL.Metrics {
				if lf.IsRegexp {
					if !qm.EnableDeduplication || !qm.shouldNotBeModified(me.LabelFilters, label) {
						me.LabelFilters = appendOrMergeRegexpLF(me.LabelFilters, lf)
					}
				} else {
					me.LabelFilters = replaceLFByName(me.LabelFilters, lf)
				}
			}
		}
	}

	// Update label filters
	metricsql.VisitAll(newExpr, modifyLabelFilter)

	return newExpr
}

// shouldNotBeModified helps to understand whether the original label filters have to be modified.
func (qm *QueryModifier) shouldNotBeModified(filters []metricsql.LabelFilter, label string) bool {
	if qm.ACL.Fullaccess {
		return true
	}

	seen := 0
	seenUnmodified := 0

	acl := qm.ACL.Metrics[label]

	for _, filter := range filters {
		if filter.Label == label && !filter.IsNegative && acl.IsRegexp && !acl.IsNegative {
			seen++

			if !filter.IsRegexp || isFakePositiveRegexp(filter) {
				re, err := metricsql.CompileRegexpAnchored(acl.Value)
				if err == nil && re.MatchString(filter.Value) {
					seenUnmodified++
					continue
				}
			}

			if filter.IsRegexp {
				if filter.Value == acl.Value {
					seenUnmodified++
					continue
				}
			}
		}
	}

	return seen > 0 && seen == seenUnmodified
}

// NewQueryModifier returns a QueryModifier containing an ACL built from rawACL.
func NewQueryModifier(rawACL string) (QueryModifier, error) {
	acl, err := NewACL(rawACL)
	return QueryModifier{ACL: acl}, err
}

// appendOrMergeRegexpLF appends label filter or merges its value in case it's a regexp with the same label name and of the same type (negative / positive).
func appendOrMergeRegexpLF(filters []metricsql.LabelFilter, newFilter metricsql.LabelFilter) []metricsql.LabelFilter {
	newFilters := make([]metricsql.LabelFilter, 0, cap(filters)+1)

	// In case we merge original filter value with newFilter, we'd like to skip adding newFilter to the resulting set.
	skipAddingNewFilter := false

	for _, filter := range filters {
		// Inspect label filters with the target name
		if filter.Label == newFilter.Label {
			// Inspect regexp filters of the same type (negative, positive)
			if filter.IsRegexp && newFilter.IsRegexp && filter.IsNegative == newFilter.IsNegative {
				skipAddingNewFilter = true
				// Merge only negative regexps, because merge for positive regexp will expose data
				if filter.Value != "" && filter.IsNegative {
					filter.Value = fmt.Sprintf("%s|%s", filter.Value, newFilter.Value)
				} else {
					filter.Value = newFilter.Value
				}
			}
		}
		newFilters = append(newFilters, filter)
	}

	if !skipAddingNewFilter {
		newFilters = append(newFilters, newFilter)
	}
	return newFilters
}

// replaceLFByName drops all label filters with the matching name and then appends the supplied filter.
func replaceLFByName(filters []metricsql.LabelFilter, newFilter metricsql.LabelFilter) []metricsql.LabelFilter {
	newFilters := make([]metricsql.LabelFilter, 0, cap(filters)+1)

	// Drop all label filters with the matching name
	for _, filter := range filters {
		if filter.Label != newFilter.Label {
			newFilters = append(newFilters, filter)
		}
	}

	newFilters = append(newFilters, newFilter)
	return newFilters
}

// isFakePositiveRegexp returns true if the given filter is a positive regexp that doesn't contain special symbols, e.g. namespace=~"kube-system"
func isFakePositiveRegexp(filter metricsql.LabelFilter) bool {
	return filter.IsRegexp && !filter.IsNegative && !strings.ContainsAny(filter.Value, RegexpSymbols)
}
