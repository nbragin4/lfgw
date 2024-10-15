package querymodifier

import (
	"fmt"
	"os"
	"strings"

	"github.com/VictoriaMetrics/metricsql"
	"gopkg.in/yaml.v3"
)

// ACLs stores a parsed YAML with role definitions
type ACLs map[string]ACL

// rolesToRawACL returns a comma-separated list of ACL definitions for all specified roles. Basically, it lets you dynamically generate a raw ACL as if it was supplied through acl.yaml. To support Assumed Roles, unknown roles are treated as ACL definitions.
func (a ACLs) rolesToRawACL(roles []string, label string, assumedRolesEnabled bool) (string, error) {
	rawACLs := make([]string, 0, len(roles))

	// FIXME: implement this code for multiple labels per ACL
	for _, role := range roles {
		acl, exists := a[role]
		if exists {
			// NOTE: You should never see an empty definitions in .RawACL as those should be removed by toSlice further down the process. The error check below is not necessary, is left as an additional safeguard for now and might get removed in the future.
			if acl.MetricsMeta[label].RawACL == "" {
				return "", fmt.Errorf("%s role contains empty rawACL", role)
			}
			if acl.MetricsMeta[label].RawACL == ".*" {
				return ".*", nil
			}
			rawACLs = append(rawACLs, acl.MetricsMeta[label].RawACL)
		} else if assumedRolesEnabled {
			// NOTE: Role names are not linted, so they may contain regular expressions, including the admin definition: .*
			rawACLs = append(rawACLs, role)
		}
	}

	rawACL := strings.Join(rawACLs, ", ")
	if rawACL == "" {
		return "", fmt.Errorf("constructed empty rawACL")
	}

	return rawACL, nil
}

// NewACLsFromFile loads ACL from a file or returns an empty ACLs instance if path is empty
func NewACLsFromFile(path string) (ACLs, error) {
	acls := make(ACLs)

	path = strings.TrimSpace(path)
	if path == "" {
		return acls, nil
	}

	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return ACLs{}, err
	}

	var aclYaml map[string]map[string]map[string]string

	err = yaml.Unmarshal(yamlFile, &aclYaml)
	if err != nil {
		return ACLs{}, err
	}

	for role, roleData := range aclYaml {
		rawACL, err := yaml.Marshal(roleData)
		if err != nil {
			return ACLs{}, fmt.Errorf("failed to marshal role data for %s: %w", role, err)
		}

		acl, err := NewACL(string(rawACL))
		if err != nil {
			return ACLs{}, fmt.Errorf("failed to create ACL for role %s: %w", role, err)
		}

		acls[role] = acl
	}

	return acls, nil
}

// GetUserACL takes a list of roles found in an OIDC claim and constructs an ACL based on them.
// If assumed roles are disabled, then only known roles (present in app.ACLs) are considered.
func (a ACLs) GetUserACL(oidcRoles []string, assumedRolesEnabled bool) (ACL, error) {
	var combinedACL ACL
	combinedACL.Metrics = make(map[string]metricsql.LabelFilter)
	combinedACL.MetricsMeta = make(map[string]LabelFilterData)

	for _, role := range oidcRoles {
		acl, exists := a[role]
		if exists {
			for label, lf := range acl.Metrics {
				if existingLF, ok := combinedACL.Metrics[label]; ok {
					combinedACL.Metrics[label] = mergeLabelFilters(existingLF, lf)
				} else {
					combinedACL.Metrics[label] = lf
				}
			}
		} else if assumedRolesEnabled {
			assumedACL, err := NewACL(fmt.Sprintf("metrics:\n  namespace: %s", role))
			if err != nil {
				return ACL{}, fmt.Errorf("failed to create assumed ACL for role %s: %w", role, err)
			}
			for label, lf := range assumedACL.Metrics {
				if existingLF, ok := combinedACL.Metrics[label]; ok {
					combinedACL.Metrics[label] = mergeLabelFilters(existingLF, lf)
				} else {
					combinedACL.Metrics[label] = lf
				}
			}
		}
	}

	if len(combinedACL.Metrics) == 0 {
		return ACL{}, fmt.Errorf("no matching roles found")
	}

	for label, lf := range combinedACL.Metrics {
		RawACL, err := a.rolesToRawACL(oidcRoles, label, assumedRolesEnabled)
		if err != nil {
			return ACL{}, err
		}
		metadata := LabelFilterData{
			Fullaccess: isFullAccess(lf),
			RawACL:     RawACL,
		}
		combinedACL.MetricsMeta[label] = metadata
	}
	return combinedACL, nil
}

// mergeLabelFilters combines two LabelFilters
func mergeLabelFilters(lf1, lf2 metricsql.LabelFilter) metricsql.LabelFilter {
	if lf1.Value == ".*" || lf2.Value == ".*" {
		return metricsql.LabelFilter{
			Label:      lf1.Label,
			Value:      ".*",
			IsRegexp:   true,
			IsNegative: lf1.IsNegative && lf2.IsNegative,
		}
	}
	return metricsql.LabelFilter{
		Label:      lf1.Label,
		Value:      fmt.Sprintf("%s|%s", lf1.Value, lf2.Value),
		IsRegexp:   true,
		IsNegative: lf1.IsNegative && lf2.IsNegative,
	}
}
