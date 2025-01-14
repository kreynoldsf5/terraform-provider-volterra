//
// Copyright (c) 2022 F5, Inc. All rights reserved.
// Code generated by ves-gen-schema-go. DO NOT EDIT.
//
package alert_receiver

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

func (m *ConfirmAlertReceiverRequest) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *ConfirmAlertReceiverRequest) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *ConfirmAlertReceiverRequest) DeepCopy() *ConfirmAlertReceiverRequest {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &ConfirmAlertReceiverRequest{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *ConfirmAlertReceiverRequest) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *ConfirmAlertReceiverRequest) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return ConfirmAlertReceiverRequestValidator().Validate(ctx, m, opts...)
}

type ValidateConfirmAlertReceiverRequest struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateConfirmAlertReceiverRequest) NamespaceValidationRuleHandler(rules map[string]string) (db.ValidatorFunc, error) {

	validatorFn, err := db.NewStringValidationRuleHandler(rules)
	if err != nil {
		return nil, errors.Wrap(err, "ValidationRuleHandler for namespace")
	}

	return validatorFn, nil
}

func (v *ValidateConfirmAlertReceiverRequest) VerificationCodeValidationRuleHandler(rules map[string]string) (db.ValidatorFunc, error) {

	validatorFn, err := db.NewStringValidationRuleHandler(rules)
	if err != nil {
		return nil, errors.Wrap(err, "ValidationRuleHandler for verification_code")
	}

	return validatorFn, nil
}

func (v *ValidateConfirmAlertReceiverRequest) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*ConfirmAlertReceiverRequest)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *ConfirmAlertReceiverRequest got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	if fv, exists := v.FldValidators["name"]; exists {

		vOpts := append(opts, db.WithValidateField("name"))
		if err := fv(ctx, m.GetName(), vOpts...); err != nil {
			return err
		}

	}

	if fv, exists := v.FldValidators["namespace"]; exists {

		vOpts := append(opts, db.WithValidateField("namespace"))
		if err := fv(ctx, m.GetNamespace(), vOpts...); err != nil {
			return err
		}

	}

	if fv, exists := v.FldValidators["verification_code"]; exists {

		vOpts := append(opts, db.WithValidateField("verification_code"))
		if err := fv(ctx, m.GetVerificationCode(), vOpts...); err != nil {
			return err
		}

	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultConfirmAlertReceiverRequestValidator = func() *ValidateConfirmAlertReceiverRequest {
	v := &ValidateConfirmAlertReceiverRequest{FldValidators: map[string]db.ValidatorFunc{}}

	var (
		err error
		vFn db.ValidatorFunc
	)
	_, _ = err, vFn
	vFnMap := map[string]db.ValidatorFunc{}
	_ = vFnMap

	vrhNamespace := v.NamespaceValidationRuleHandler
	rulesNamespace := map[string]string{
		"ves.io.schema.rules.message.required": "true",
	}
	vFn, err = vrhNamespace(rulesNamespace)
	if err != nil {
		errMsg := fmt.Sprintf("ValidationRuleHandler for ConfirmAlertReceiverRequest.namespace: %s", err)
		panic(errMsg)
	}
	v.FldValidators["namespace"] = vFn

	vrhVerificationCode := v.VerificationCodeValidationRuleHandler
	rulesVerificationCode := map[string]string{
		"ves.io.schema.rules.string.len_bytes": "6",
	}
	vFn, err = vrhVerificationCode(rulesVerificationCode)
	if err != nil {
		errMsg := fmt.Sprintf("ValidationRuleHandler for ConfirmAlertReceiverRequest.verification_code: %s", err)
		panic(errMsg)
	}
	v.FldValidators["verification_code"] = vFn

	return v
}()

func ConfirmAlertReceiverRequestValidator() db.Validator {
	return DefaultConfirmAlertReceiverRequestValidator
}

// augmented methods on protoc/std generated struct

func (m *ConfirmAlertReceiverResponse) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *ConfirmAlertReceiverResponse) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *ConfirmAlertReceiverResponse) DeepCopy() *ConfirmAlertReceiverResponse {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &ConfirmAlertReceiverResponse{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *ConfirmAlertReceiverResponse) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *ConfirmAlertReceiverResponse) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return ConfirmAlertReceiverResponseValidator().Validate(ctx, m, opts...)
}

type ValidateConfirmAlertReceiverResponse struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateConfirmAlertReceiverResponse) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*ConfirmAlertReceiverResponse)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *ConfirmAlertReceiverResponse got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultConfirmAlertReceiverResponseValidator = func() *ValidateConfirmAlertReceiverResponse {
	v := &ValidateConfirmAlertReceiverResponse{FldValidators: map[string]db.ValidatorFunc{}}

	return v
}()

func ConfirmAlertReceiverResponseValidator() db.Validator {
	return DefaultConfirmAlertReceiverResponseValidator
}

// augmented methods on protoc/std generated struct

func (m *TestAlertReceiverRequest) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *TestAlertReceiverRequest) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *TestAlertReceiverRequest) DeepCopy() *TestAlertReceiverRequest {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &TestAlertReceiverRequest{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *TestAlertReceiverRequest) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *TestAlertReceiverRequest) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return TestAlertReceiverRequestValidator().Validate(ctx, m, opts...)
}

type ValidateTestAlertReceiverRequest struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateTestAlertReceiverRequest) NamespaceValidationRuleHandler(rules map[string]string) (db.ValidatorFunc, error) {

	validatorFn, err := db.NewStringValidationRuleHandler(rules)
	if err != nil {
		return nil, errors.Wrap(err, "ValidationRuleHandler for namespace")
	}

	return validatorFn, nil
}

func (v *ValidateTestAlertReceiverRequest) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*TestAlertReceiverRequest)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *TestAlertReceiverRequest got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	if fv, exists := v.FldValidators["name"]; exists {

		vOpts := append(opts, db.WithValidateField("name"))
		if err := fv(ctx, m.GetName(), vOpts...); err != nil {
			return err
		}

	}

	if fv, exists := v.FldValidators["namespace"]; exists {

		vOpts := append(opts, db.WithValidateField("namespace"))
		if err := fv(ctx, m.GetNamespace(), vOpts...); err != nil {
			return err
		}

	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultTestAlertReceiverRequestValidator = func() *ValidateTestAlertReceiverRequest {
	v := &ValidateTestAlertReceiverRequest{FldValidators: map[string]db.ValidatorFunc{}}

	var (
		err error
		vFn db.ValidatorFunc
	)
	_, _ = err, vFn
	vFnMap := map[string]db.ValidatorFunc{}
	_ = vFnMap

	vrhNamespace := v.NamespaceValidationRuleHandler
	rulesNamespace := map[string]string{
		"ves.io.schema.rules.message.required": "true",
	}
	vFn, err = vrhNamespace(rulesNamespace)
	if err != nil {
		errMsg := fmt.Sprintf("ValidationRuleHandler for TestAlertReceiverRequest.namespace: %s", err)
		panic(errMsg)
	}
	v.FldValidators["namespace"] = vFn

	return v
}()

func TestAlertReceiverRequestValidator() db.Validator {
	return DefaultTestAlertReceiverRequestValidator
}

// augmented methods on protoc/std generated struct

func (m *TestAlertReceiverResponse) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *TestAlertReceiverResponse) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *TestAlertReceiverResponse) DeepCopy() *TestAlertReceiverResponse {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &TestAlertReceiverResponse{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *TestAlertReceiverResponse) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *TestAlertReceiverResponse) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return TestAlertReceiverResponseValidator().Validate(ctx, m, opts...)
}

type ValidateTestAlertReceiverResponse struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateTestAlertReceiverResponse) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*TestAlertReceiverResponse)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *TestAlertReceiverResponse got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultTestAlertReceiverResponseValidator = func() *ValidateTestAlertReceiverResponse {
	v := &ValidateTestAlertReceiverResponse{FldValidators: map[string]db.ValidatorFunc{}}

	return v
}()

func TestAlertReceiverResponseValidator() db.Validator {
	return DefaultTestAlertReceiverResponseValidator
}

// augmented methods on protoc/std generated struct

func (m *VerifyAlertReceiverRequest) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *VerifyAlertReceiverRequest) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *VerifyAlertReceiverRequest) DeepCopy() *VerifyAlertReceiverRequest {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &VerifyAlertReceiverRequest{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *VerifyAlertReceiverRequest) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *VerifyAlertReceiverRequest) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return VerifyAlertReceiverRequestValidator().Validate(ctx, m, opts...)
}

type ValidateVerifyAlertReceiverRequest struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateVerifyAlertReceiverRequest) NamespaceValidationRuleHandler(rules map[string]string) (db.ValidatorFunc, error) {

	validatorFn, err := db.NewStringValidationRuleHandler(rules)
	if err != nil {
		return nil, errors.Wrap(err, "ValidationRuleHandler for namespace")
	}

	return validatorFn, nil
}

func (v *ValidateVerifyAlertReceiverRequest) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*VerifyAlertReceiverRequest)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *VerifyAlertReceiverRequest got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	if fv, exists := v.FldValidators["name"]; exists {

		vOpts := append(opts, db.WithValidateField("name"))
		if err := fv(ctx, m.GetName(), vOpts...); err != nil {
			return err
		}

	}

	if fv, exists := v.FldValidators["namespace"]; exists {

		vOpts := append(opts, db.WithValidateField("namespace"))
		if err := fv(ctx, m.GetNamespace(), vOpts...); err != nil {
			return err
		}

	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultVerifyAlertReceiverRequestValidator = func() *ValidateVerifyAlertReceiverRequest {
	v := &ValidateVerifyAlertReceiverRequest{FldValidators: map[string]db.ValidatorFunc{}}

	var (
		err error
		vFn db.ValidatorFunc
	)
	_, _ = err, vFn
	vFnMap := map[string]db.ValidatorFunc{}
	_ = vFnMap

	vrhNamespace := v.NamespaceValidationRuleHandler
	rulesNamespace := map[string]string{
		"ves.io.schema.rules.message.required": "true",
	}
	vFn, err = vrhNamespace(rulesNamespace)
	if err != nil {
		errMsg := fmt.Sprintf("ValidationRuleHandler for VerifyAlertReceiverRequest.namespace: %s", err)
		panic(errMsg)
	}
	v.FldValidators["namespace"] = vFn

	return v
}()

func VerifyAlertReceiverRequestValidator() db.Validator {
	return DefaultVerifyAlertReceiverRequestValidator
}

// augmented methods on protoc/std generated struct

func (m *VerifyAlertReceiverResponse) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *VerifyAlertReceiverResponse) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *VerifyAlertReceiverResponse) DeepCopy() *VerifyAlertReceiverResponse {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &VerifyAlertReceiverResponse{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *VerifyAlertReceiverResponse) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *VerifyAlertReceiverResponse) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return VerifyAlertReceiverResponseValidator().Validate(ctx, m, opts...)
}

type ValidateVerifyAlertReceiverResponse struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateVerifyAlertReceiverResponse) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*VerifyAlertReceiverResponse)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *VerifyAlertReceiverResponse got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultVerifyAlertReceiverResponseValidator = func() *ValidateVerifyAlertReceiverResponse {
	v := &ValidateVerifyAlertReceiverResponse{FldValidators: map[string]db.ValidatorFunc{}}

	return v
}()

func VerifyAlertReceiverResponseValidator() db.Validator {
	return DefaultVerifyAlertReceiverResponseValidator
}
