//
// Copyright (c) 2018 Volterra, Inc. All rights reserved.
// Code generated by ves-gen-schema-go. DO NOT EDIT.
//
package virtual_host_dns_info

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

func (m *DnsInfo) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *DnsInfo) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *DnsInfo) DeepCopy() *DnsInfo {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &DnsInfo{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *DnsInfo) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *DnsInfo) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return DnsInfoValidator().Validate(ctx, m, opts...)
}

type ValidateDnsInfo struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateDnsInfo) IpAddressValidationRuleHandler(rules map[string]string) (db.ValidatorFunc, error) {

	validatorFn, err := db.NewStringValidationRuleHandler(rules)
	if err != nil {
		return nil, errors.Wrap(err, "ValidationRuleHandler for ip_address")
	}

	return validatorFn, nil
}

func (v *ValidateDnsInfo) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*DnsInfo)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *DnsInfo got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	if fv, exists := v.FldValidators["ip_address"]; exists {

		vOpts := append(opts, db.WithValidateField("ip_address"))
		if err := fv(ctx, m.GetIpAddress(), vOpts...); err != nil {
			return err
		}

	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultDnsInfoValidator = func() *ValidateDnsInfo {
	v := &ValidateDnsInfo{FldValidators: map[string]db.ValidatorFunc{}}

	var (
		err error
		vFn db.ValidatorFunc
	)
	_, _ = err, vFn
	vFnMap := map[string]db.ValidatorFunc{}
	_ = vFnMap

	vrhIpAddress := v.IpAddressValidationRuleHandler
	rulesIpAddress := map[string]string{
		"ves.io.schema.rules.string.ip": "true",
	}
	vFn, err = vrhIpAddress(rulesIpAddress)
	if err != nil {
		errMsg := fmt.Sprintf("ValidationRuleHandler for DnsInfo.ip_address: %s", err)
		panic(errMsg)
	}
	v.FldValidators["ip_address"] = vFn

	return v
}()

func DnsInfoValidator() db.Validator {
	return DefaultDnsInfoValidator
}

// augmented methods on protoc/std generated struct

func (m *GlobalSpecType) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *GlobalSpecType) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *GlobalSpecType) DeepCopy() *GlobalSpecType {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &GlobalSpecType{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *GlobalSpecType) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *GlobalSpecType) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return GlobalSpecTypeValidator().Validate(ctx, m, opts...)
}

func (m *GlobalSpecType) GetDRefInfo() ([]db.DRefInfo, error) {
	if m == nil {
		return nil, nil
	}

	return m.GetVirtualHostDRefInfo()

}

func (m *GlobalSpecType) GetVirtualHostDRefInfo() ([]db.DRefInfo, error) {
	refs := m.GetVirtualHost()
	if len(refs) == 0 {
		return nil, nil
	}
	drInfos := make([]db.DRefInfo, 0, len(refs))
	for i, ref := range refs {
		if ref == nil {
			return nil, fmt.Errorf("GlobalSpecType.virtual_host[%d] has a nil value", i)
		}
		// resolve kind to type if needed at DBObject.GetDRefInfo()
		drInfos = append(drInfos, db.DRefInfo{
			RefdType:   "virtual_host.Object",
			RefdUID:    ref.Uid,
			RefdTenant: ref.Tenant,
			RefdNS:     ref.Namespace,
			RefdName:   ref.Name,
			DRField:    "virtual_host",
			Ref:        ref,
		})
	}
	return drInfos, nil

}

// GetVirtualHostDBEntries returns the db.Entry corresponding to the ObjRefType from the default Table
func (m *GlobalSpecType) GetVirtualHostDBEntries(ctx context.Context, d db.Interface) ([]db.Entry, error) {
	var entries []db.Entry
	refdType, err := d.TypeForEntryKind("", "", "virtual_host.Object")
	if err != nil {
		return nil, errors.Wrap(err, "Cannot find type for kind: virtual_host")
	}
	for _, ref := range m.GetVirtualHost() {
		refdEnt, err := d.GetReferredEntry(ctx, refdType, ref, db.WithRefOpOptions(db.OpWithReadRefFromInternalTable()))
		if err != nil {
			return nil, errors.Wrap(err, "Getting referred entry")
		}
		if refdEnt != nil {
			entries = append(entries, refdEnt)
		}
	}

	return entries, nil
}

type ValidateGlobalSpecType struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateGlobalSpecType) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*GlobalSpecType)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *GlobalSpecType got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	if fv, exists := v.FldValidators["dns_info"]; exists {

		vOpts := append(opts, db.WithValidateField("dns_info"))
		for idx, item := range m.GetDnsInfo() {
			vOpts := append(vOpts, db.WithValidateRepItem(idx))
			if err := fv(ctx, item, vOpts...); err != nil {
				return err
			}
		}

	}

	if fv, exists := v.FldValidators["host_name"]; exists {

		vOpts := append(opts, db.WithValidateField("host_name"))
		if err := fv(ctx, m.GetHostName(), vOpts...); err != nil {
			return err
		}

	}

	if fv, exists := v.FldValidators["virtual_host"]; exists {

		vOpts := append(opts, db.WithValidateField("virtual_host"))
		for idx, item := range m.GetVirtualHost() {
			vOpts := append(vOpts, db.WithValidateRepItem(idx))
			if err := fv(ctx, item, vOpts...); err != nil {
				return err
			}
		}

	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultGlobalSpecTypeValidator = func() *ValidateGlobalSpecType {
	v := &ValidateGlobalSpecType{FldValidators: map[string]db.ValidatorFunc{}}

	v.FldValidators["dns_info"] = DnsInfoValidator().Validate

	return v
}()

func GlobalSpecTypeValidator() db.Validator {
	return DefaultGlobalSpecTypeValidator
}

// augmented methods on protoc/std generated struct

func (m *SpecType) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *SpecType) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *SpecType) DeepCopy() *SpecType {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &SpecType{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *SpecType) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *SpecType) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return SpecTypeValidator().Validate(ctx, m, opts...)
}

func (m *SpecType) GetDRefInfo() ([]db.DRefInfo, error) {
	if m == nil {
		return nil, nil
	}

	return m.GetGcSpecDRefInfo()

}

// GetDRefInfo for the field's type
func (m *SpecType) GetGcSpecDRefInfo() ([]db.DRefInfo, error) {
	if m.GetGcSpec() == nil {
		return nil, nil
	}

	drInfos, err := m.GetGcSpec().GetDRefInfo()
	if err != nil {
		return nil, errors.Wrap(err, "GetGcSpec().GetDRefInfo() FAILED")
	}
	for i := range drInfos {
		dri := &drInfos[i]
		dri.DRField = "gc_spec." + dri.DRField
	}
	return drInfos, err

}

type ValidateSpecType struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateSpecType) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*SpecType)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *SpecType got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	if fv, exists := v.FldValidators["gc_spec"]; exists {

		vOpts := append(opts, db.WithValidateField("gc_spec"))
		if err := fv(ctx, m.GetGcSpec(), vOpts...); err != nil {
			return err
		}

	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultSpecTypeValidator = func() *ValidateSpecType {
	v := &ValidateSpecType{FldValidators: map[string]db.ValidatorFunc{}}

	v.FldValidators["gc_spec"] = GlobalSpecTypeValidator().Validate

	return v
}()

func SpecTypeValidator() db.Validator {
	return DefaultSpecTypeValidator
}
