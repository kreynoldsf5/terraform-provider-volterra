//
// Copyright (c) 2018 Volterra, Inc. All rights reserved.
// Code generated by ves-gen-schema-go. DO NOT EDIT.
//
package vesenv

import (
	"context"
	"fmt"
	"strings"

	"github.com/gogo/protobuf/proto"

	"gopkg.volterra.us/stdlib/codec"
	"gopkg.volterra.us/stdlib/db"
	"gopkg.volterra.us/stdlib/errors"
)

var (
	// dummy imports in case file has no message with Refs
	_ db.Interface
	_ = errors.Wrap
	_ = strings.Split
)

// augmented methods on protoc/std generated struct

func (m *APIGroupChoice) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *APIGroupChoice) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *APIGroupChoice) DeepCopy() *APIGroupChoice {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &APIGroupChoice{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *APIGroupChoice) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *APIGroupChoice) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return APIGroupChoiceValidator().Validate(ctx, m, opts...)
}

type ValidateAPIGroupChoice struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateAPIGroupChoice) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*APIGroupChoice)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *APIGroupChoice got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	switch m.GetChoice().(type) {
	case *APIGroupChoice_InfrastructureDemoAccessRead:
		if fv, exists := v.FldValidators["choice.infrastructure_demo_access_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_InfrastructureDemoAccessRead).InfrastructureDemoAccessRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("infrastructure_demo_access_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoBillingRead:
		if fv, exists := v.FldValidators["choice.ves_io_billing_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoBillingRead).VesIoBillingRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_billing_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoBillingWrite:
		if fv, exists := v.FldValidators["choice.ves_io_billing_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoBillingWrite).VesIoBillingWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_billing_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoGeneralRead:
		if fv, exists := v.FldValidators["choice.ves_io_general_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoGeneralRead).VesIoGeneralRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_general_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoGeneralWrite:
		if fv, exists := v.FldValidators["choice.ves_io_general_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoGeneralWrite).VesIoGeneralWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_general_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoIaasCaasRead:
		if fv, exists := v.FldValidators["choice.ves_io_iaas_caas_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoIaasCaasRead).VesIoIaasCaasRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_iaas_caas_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoIaasCaasWrite:
		if fv, exists := v.FldValidators["choice.ves_io_iaas_caas_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoIaasCaasWrite).VesIoIaasCaasWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_iaas_caas_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoInfraMonitorRead:
		if fv, exists := v.FldValidators["choice.ves_io_infra_monitor_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoInfraMonitorRead).VesIoInfraMonitorRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_infra_monitor_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoInfraMonitorWrite:
		if fv, exists := v.FldValidators["choice.ves_io_infra_monitor_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoInfraMonitorWrite).VesIoInfraMonitorWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_infra_monitor_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoInfrastructureRead:
		if fv, exists := v.FldValidators["choice.ves_io_infrastructure_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoInfrastructureRead).VesIoInfrastructureRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_infrastructure_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoInfrastructureWrite:
		if fv, exists := v.FldValidators["choice.ves_io_infrastructure_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoInfrastructureWrite).VesIoInfrastructureWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_infrastructure_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoInternalRead:
		if fv, exists := v.FldValidators["choice.ves_io_internal_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoInternalRead).VesIoInternalRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_internal_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoInternalWrite:
		if fv, exists := v.FldValidators["choice.ves_io_internal_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoInternalWrite).VesIoInternalWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_internal_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoK8SRead:
		if fv, exists := v.FldValidators["choice.ves_io_k8s_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoK8SRead).VesIoK8SRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_k8s_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoK8SWrite:
		if fv, exists := v.FldValidators["choice.ves_io_k8s_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoK8SWrite).VesIoK8SWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_k8s_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoLabelsRead:
		if fv, exists := v.FldValidators["choice.ves_io_labels_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoLabelsRead).VesIoLabelsRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_labels_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoLabelsWrite:
		if fv, exists := v.FldValidators["choice.ves_io_labels_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoLabelsWrite).VesIoLabelsWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_labels_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoLocalK8SWrite:
		if fv, exists := v.FldValidators["choice.ves_io_local_k8s_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoLocalK8SWrite).VesIoLocalK8SWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_local_k8s_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoMonitorRead:
		if fv, exists := v.FldValidators["choice.ves_io_monitor_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoMonitorRead).VesIoMonitorRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_monitor_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoMonitorWrite:
		if fv, exists := v.FldValidators["choice.ves_io_monitor_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoMonitorWrite).VesIoMonitorWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_monitor_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoNetworkRead:
		if fv, exists := v.FldValidators["choice.ves_io_network_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoNetworkRead).VesIoNetworkRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_network_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoNetworkWrite:
		if fv, exists := v.FldValidators["choice.ves_io_network_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoNetworkWrite).VesIoNetworkWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_network_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoProxyMonitorRead:
		if fv, exists := v.FldValidators["choice.ves_io_proxy_monitor_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoProxyMonitorRead).VesIoProxyMonitorRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_proxy_monitor_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoProxyMonitorWrite:
		if fv, exists := v.FldValidators["choice.ves_io_proxy_monitor_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoProxyMonitorWrite).VesIoProxyMonitorWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_proxy_monitor_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoProxyRead:
		if fv, exists := v.FldValidators["choice.ves_io_proxy_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoProxyRead).VesIoProxyRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_proxy_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoProxySecurityRead:
		if fv, exists := v.FldValidators["choice.ves_io_proxy_security_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoProxySecurityRead).VesIoProxySecurityRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_proxy_security_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoProxySecurityWrite:
		if fv, exists := v.FldValidators["choice.ves_io_proxy_security_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoProxySecurityWrite).VesIoProxySecurityWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_proxy_security_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoProxyWafRead:
		if fv, exists := v.FldValidators["choice.ves_io_proxy_waf_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoProxyWafRead).VesIoProxyWafRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_proxy_waf_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoProxyWafWrite:
		if fv, exists := v.FldValidators["choice.ves_io_proxy_waf_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoProxyWafWrite).VesIoProxyWafWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_proxy_waf_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoProxyWrite:
		if fv, exists := v.FldValidators["choice.ves_io_proxy_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoProxyWrite).VesIoProxyWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_proxy_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoSecretsRead:
		if fv, exists := v.FldValidators["choice.ves_io_secrets_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoSecretsRead).VesIoSecretsRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_secrets_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoSecretsWrite:
		if fv, exists := v.FldValidators["choice.ves_io_secrets_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoSecretsWrite).VesIoSecretsWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_secrets_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoSystemSrv6NetworkSliceReadWrite:
		if fv, exists := v.FldValidators["choice.ves_io_system_srv6_network_slice_read_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoSystemSrv6NetworkSliceReadWrite).VesIoSystemSrv6NetworkSliceReadWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_system_srv6_network_slice_read_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoSystemVirtualNetworkReadWrite:
		if fv, exists := v.FldValidators["choice.ves_io_system_virtual_network_read_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoSystemVirtualNetworkReadWrite).VesIoSystemVirtualNetworkReadWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_system_virtual_network_read_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoUamAdminRead:
		if fv, exists := v.FldValidators["choice.ves_io_uam_admin_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoUamAdminRead).VesIoUamAdminRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_uam_admin_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoUamAdminWrite:
		if fv, exists := v.FldValidators["choice.ves_io_uam_admin_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoUamAdminWrite).VesIoUamAdminWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_uam_admin_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoUamRead:
		if fv, exists := v.FldValidators["choice.ves_io_uam_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoUamRead).VesIoUamRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_uam_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoUamWrite:
		if fv, exists := v.FldValidators["choice.ves_io_uam_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoUamWrite).VesIoUamWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_uam_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoVirtualSitesRead:
		if fv, exists := v.FldValidators["choice.ves_io_virtual_sites_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoVirtualSitesRead).VesIoVirtualSitesRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_virtual_sites_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoVirtualSitesWrite:
		if fv, exists := v.FldValidators["choice.ves_io_virtual_sites_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoVirtualSitesWrite).VesIoVirtualSitesWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_virtual_sites_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoVoltShareRead:
		if fv, exists := v.FldValidators["choice.ves_io_volt_share_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoVoltShareRead).VesIoVoltShareRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_volt_share_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoVoltShareWrite:
		if fv, exists := v.FldValidators["choice.ves_io_volt_share_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoVoltShareWrite).VesIoVoltShareWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_volt_share_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoWebAccessRead:
		if fv, exists := v.FldValidators["choice.ves_io_web_access_read"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoWebAccessRead).VesIoWebAccessRead
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_web_access_read"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *APIGroupChoice_VesIoWebAccessWrite:
		if fv, exists := v.FldValidators["choice.ves_io_web_access_write"]; exists {
			val := m.GetChoice().(*APIGroupChoice_VesIoWebAccessWrite).VesIoWebAccessWrite
			vOpts := append(opts,
				db.WithValidateField("choice"),
				db.WithValidateField("ves_io_web_access_write"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}

	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultAPIGroupChoiceValidator = func() *ValidateAPIGroupChoice {
	v := &ValidateAPIGroupChoice{FldValidators: map[string]db.ValidatorFunc{}}

	return v
}()

func APIGroupChoiceValidator() db.Validator {
	return DefaultAPIGroupChoiceValidator
}
