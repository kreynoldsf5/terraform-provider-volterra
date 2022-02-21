//
// Copyright (c) 2018 Volterra, Inc. All rights reserved.
// Code generated by ves-gen-schema-go. DO NOT EDIT.
//
package malicious_user_mitigation

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

func (m *CreateSpecType) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *CreateSpecType) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *CreateSpecType) DeepCopy() *CreateSpecType {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &CreateSpecType{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *CreateSpecType) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *CreateSpecType) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return CreateSpecTypeValidator().Validate(ctx, m, opts...)
}

type ValidateCreateSpecType struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateCreateSpecType) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*CreateSpecType)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *CreateSpecType got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	if fv, exists := v.FldValidators["mitigation_type"]; exists {

		vOpts := append(opts, db.WithValidateField("mitigation_type"))
		if err := fv(ctx, m.GetMitigationType(), vOpts...); err != nil {
			return err
		}

	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultCreateSpecTypeValidator = func() *ValidateCreateSpecType {
	v := &ValidateCreateSpecType{FldValidators: map[string]db.ValidatorFunc{}}

	v.FldValidators["mitigation_type"] = MaliciousUserMitigationTypeValidator().Validate

	return v
}()

func CreateSpecTypeValidator() db.Validator {
	return DefaultCreateSpecTypeValidator
}

// augmented methods on protoc/std generated struct

func (m *GetSpecType) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *GetSpecType) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *GetSpecType) DeepCopy() *GetSpecType {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &GetSpecType{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *GetSpecType) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *GetSpecType) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return GetSpecTypeValidator().Validate(ctx, m, opts...)
}

type ValidateGetSpecType struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateGetSpecType) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*GetSpecType)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *GetSpecType got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	if fv, exists := v.FldValidators["mitigation_type"]; exists {

		vOpts := append(opts, db.WithValidateField("mitigation_type"))
		if err := fv(ctx, m.GetMitigationType(), vOpts...); err != nil {
			return err
		}

	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultGetSpecTypeValidator = func() *ValidateGetSpecType {
	v := &ValidateGetSpecType{FldValidators: map[string]db.ValidatorFunc{}}

	v.FldValidators["mitigation_type"] = MaliciousUserMitigationTypeValidator().Validate

	return v
}()

func GetSpecTypeValidator() db.Validator {
	return DefaultGetSpecTypeValidator
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

	if fv, exists := v.FldValidators["mitigation_type"]; exists {

		vOpts := append(opts, db.WithValidateField("mitigation_type"))
		if err := fv(ctx, m.GetMitigationType(), vOpts...); err != nil {
			return err
		}

	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultGlobalSpecTypeValidator = func() *ValidateGlobalSpecType {
	v := &ValidateGlobalSpecType{FldValidators: map[string]db.ValidatorFunc{}}

	v.FldValidators["mitigation_type"] = MaliciousUserMitigationTypeValidator().Validate

	return v
}()

func GlobalSpecTypeValidator() db.Validator {
	return DefaultGlobalSpecTypeValidator
}

// augmented methods on protoc/std generated struct

func (m *MaliciousUserMitigationAction) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *MaliciousUserMitigationAction) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *MaliciousUserMitigationAction) DeepCopy() *MaliciousUserMitigationAction {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &MaliciousUserMitigationAction{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *MaliciousUserMitigationAction) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *MaliciousUserMitigationAction) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return MaliciousUserMitigationActionValidator().Validate(ctx, m, opts...)
}

type ValidateMaliciousUserMitigationAction struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateMaliciousUserMitigationAction) MitigationActionValidationRuleHandler(rules map[string]string) (db.ValidatorFunc, error) {
	validatorFn, err := db.NewMessageValidationRuleHandler(rules)
	if err != nil {
		return nil, errors.Wrap(err, "ValidationRuleHandler for mitigation_action")
	}
	return validatorFn, nil
}

func (v *ValidateMaliciousUserMitigationAction) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*MaliciousUserMitigationAction)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *MaliciousUserMitigationAction got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	if fv, exists := v.FldValidators["mitigation_action"]; exists {
		val := m.GetMitigationAction()
		vOpts := append(opts,
			db.WithValidateField("mitigation_action"),
		)
		if err := fv(ctx, val, vOpts...); err != nil {
			return err
		}
	}

	switch m.GetMitigationAction().(type) {
	case *MaliciousUserMitigationAction_None:
		if fv, exists := v.FldValidators["mitigation_action.none"]; exists {
			val := m.GetMitigationAction().(*MaliciousUserMitigationAction_None).None
			vOpts := append(opts,
				db.WithValidateField("mitigation_action"),
				db.WithValidateField("none"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *MaliciousUserMitigationAction_AlertOnly:
		if fv, exists := v.FldValidators["mitigation_action.alert_only"]; exists {
			val := m.GetMitigationAction().(*MaliciousUserMitigationAction_AlertOnly).AlertOnly
			vOpts := append(opts,
				db.WithValidateField("mitigation_action"),
				db.WithValidateField("alert_only"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *MaliciousUserMitigationAction_JavascriptChallenge:
		if fv, exists := v.FldValidators["mitigation_action.javascript_challenge"]; exists {
			val := m.GetMitigationAction().(*MaliciousUserMitigationAction_JavascriptChallenge).JavascriptChallenge
			vOpts := append(opts,
				db.WithValidateField("mitigation_action"),
				db.WithValidateField("javascript_challenge"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *MaliciousUserMitigationAction_CaptchaChallenge:
		if fv, exists := v.FldValidators["mitigation_action.captcha_challenge"]; exists {
			val := m.GetMitigationAction().(*MaliciousUserMitigationAction_CaptchaChallenge).CaptchaChallenge
			vOpts := append(opts,
				db.WithValidateField("mitigation_action"),
				db.WithValidateField("captcha_challenge"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *MaliciousUserMitigationAction_BlockTemporarily:
		if fv, exists := v.FldValidators["mitigation_action.block_temporarily"]; exists {
			val := m.GetMitigationAction().(*MaliciousUserMitigationAction_BlockTemporarily).BlockTemporarily
			vOpts := append(opts,
				db.WithValidateField("mitigation_action"),
				db.WithValidateField("block_temporarily"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}

	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultMaliciousUserMitigationActionValidator = func() *ValidateMaliciousUserMitigationAction {
	v := &ValidateMaliciousUserMitigationAction{FldValidators: map[string]db.ValidatorFunc{}}

	var (
		err error
		vFn db.ValidatorFunc
	)
	_, _ = err, vFn
	vFnMap := map[string]db.ValidatorFunc{}
	_ = vFnMap

	vrhMitigationAction := v.MitigationActionValidationRuleHandler
	rulesMitigationAction := map[string]string{
		"ves.io.schema.rules.message.required_oneof": "true",
	}
	vFn, err = vrhMitigationAction(rulesMitigationAction)
	if err != nil {
		errMsg := fmt.Sprintf("ValidationRuleHandler for MaliciousUserMitigationAction.mitigation_action: %s", err)
		panic(errMsg)
	}
	v.FldValidators["mitigation_action"] = vFn

	return v
}()

func MaliciousUserMitigationActionValidator() db.Validator {
	return DefaultMaliciousUserMitigationActionValidator
}

// augmented methods on protoc/std generated struct

func (m *MaliciousUserMitigationRule) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *MaliciousUserMitigationRule) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *MaliciousUserMitigationRule) DeepCopy() *MaliciousUserMitigationRule {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &MaliciousUserMitigationRule{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *MaliciousUserMitigationRule) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *MaliciousUserMitigationRule) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return MaliciousUserMitigationRuleValidator().Validate(ctx, m, opts...)
}

type ValidateMaliciousUserMitigationRule struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateMaliciousUserMitigationRule) ThreatLevelValidationRuleHandler(rules map[string]string) (db.ValidatorFunc, error) {

	reqdValidatorFn, err := db.NewMessageValidationRuleHandler(rules)
	if err != nil {
		return nil, errors.Wrap(err, "MessageValidationRuleHandler for threat_level")
	}
	validatorFn := func(ctx context.Context, val interface{}, opts ...db.ValidateOpt) error {
		if err := reqdValidatorFn(ctx, val, opts...); err != nil {
			return err
		}

		if err := MaliciousUserThreatLevelValidator().Validate(ctx, val, opts...); err != nil {
			return err
		}

		return nil
	}

	return validatorFn, nil
}

func (v *ValidateMaliciousUserMitigationRule) MitigationActionValidationRuleHandler(rules map[string]string) (db.ValidatorFunc, error) {

	reqdValidatorFn, err := db.NewMessageValidationRuleHandler(rules)
	if err != nil {
		return nil, errors.Wrap(err, "MessageValidationRuleHandler for mitigation_action")
	}
	validatorFn := func(ctx context.Context, val interface{}, opts ...db.ValidateOpt) error {
		if err := reqdValidatorFn(ctx, val, opts...); err != nil {
			return err
		}

		if err := MaliciousUserMitigationActionValidator().Validate(ctx, val, opts...); err != nil {
			return err
		}

		return nil
	}

	return validatorFn, nil
}

func (v *ValidateMaliciousUserMitigationRule) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*MaliciousUserMitigationRule)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *MaliciousUserMitigationRule got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	if fv, exists := v.FldValidators["mitigation_action"]; exists {

		vOpts := append(opts, db.WithValidateField("mitigation_action"))
		if err := fv(ctx, m.GetMitigationAction(), vOpts...); err != nil {
			return err
		}

	}

	if fv, exists := v.FldValidators["threat_level"]; exists {

		vOpts := append(opts, db.WithValidateField("threat_level"))
		if err := fv(ctx, m.GetThreatLevel(), vOpts...); err != nil {
			return err
		}

	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultMaliciousUserMitigationRuleValidator = func() *ValidateMaliciousUserMitigationRule {
	v := &ValidateMaliciousUserMitigationRule{FldValidators: map[string]db.ValidatorFunc{}}

	var (
		err error
		vFn db.ValidatorFunc
	)
	_, _ = err, vFn
	vFnMap := map[string]db.ValidatorFunc{}
	_ = vFnMap

	vrhThreatLevel := v.ThreatLevelValidationRuleHandler
	rulesThreatLevel := map[string]string{
		"ves.io.schema.rules.message.required": "true",
	}
	vFn, err = vrhThreatLevel(rulesThreatLevel)
	if err != nil {
		errMsg := fmt.Sprintf("ValidationRuleHandler for MaliciousUserMitigationRule.threat_level: %s", err)
		panic(errMsg)
	}
	v.FldValidators["threat_level"] = vFn

	vrhMitigationAction := v.MitigationActionValidationRuleHandler
	rulesMitigationAction := map[string]string{
		"ves.io.schema.rules.message.required": "true",
	}
	vFn, err = vrhMitigationAction(rulesMitigationAction)
	if err != nil {
		errMsg := fmt.Sprintf("ValidationRuleHandler for MaliciousUserMitigationRule.mitigation_action: %s", err)
		panic(errMsg)
	}
	v.FldValidators["mitigation_action"] = vFn

	return v
}()

func MaliciousUserMitigationRuleValidator() db.Validator {
	return DefaultMaliciousUserMitigationRuleValidator
}

// augmented methods on protoc/std generated struct

func (m *MaliciousUserMitigationType) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *MaliciousUserMitigationType) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *MaliciousUserMitigationType) DeepCopy() *MaliciousUserMitigationType {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &MaliciousUserMitigationType{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *MaliciousUserMitigationType) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *MaliciousUserMitigationType) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return MaliciousUserMitigationTypeValidator().Validate(ctx, m, opts...)
}

type ValidateMaliciousUserMitigationType struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateMaliciousUserMitigationType) RulesValidationRuleHandler(rules map[string]string) (db.ValidatorFunc, error) {

	itemsValidatorFn := func(ctx context.Context, elems []*MaliciousUserMitigationRule, opts ...db.ValidateOpt) error {
		for i, el := range elems {
			if err := MaliciousUserMitigationRuleValidator().Validate(ctx, el, opts...); err != nil {
				return errors.Wrap(err, fmt.Sprintf("element %d", i))
			}
		}
		return nil
	}
	repValFn, err := db.NewRepeatedValidationRuleHandler(rules)
	if err != nil {
		return nil, errors.Wrap(err, "Repeated ValidationRuleHandler for rules")
	}

	validatorFn := func(ctx context.Context, val interface{}, opts ...db.ValidateOpt) error {
		elems, ok := val.([]*MaliciousUserMitigationRule)
		if !ok {
			return fmt.Errorf("Repeated validation expected []*MaliciousUserMitigationRule, got %T", val)
		}
		l := []string{}
		for _, elem := range elems {
			strVal, err := codec.ToJSON(elem, codec.ToWithUseProtoFieldName())
			if err != nil {
				return errors.Wrapf(err, "Converting %v to JSON", elem)
			}
			l = append(l, strVal)
		}
		if err := repValFn(ctx, l, opts...); err != nil {
			return errors.Wrap(err, "repeated rules")
		}
		if err := itemsValidatorFn(ctx, elems, opts...); err != nil {
			return errors.Wrap(err, "items rules")
		}
		return nil
	}

	return validatorFn, nil
}

func (v *ValidateMaliciousUserMitigationType) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*MaliciousUserMitigationType)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *MaliciousUserMitigationType got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	if fv, exists := v.FldValidators["rules"]; exists {
		vOpts := append(opts, db.WithValidateField("rules"))
		if err := fv(ctx, m.GetRules(), vOpts...); err != nil {
			return err
		}

	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultMaliciousUserMitigationTypeValidator = func() *ValidateMaliciousUserMitigationType {
	v := &ValidateMaliciousUserMitigationType{FldValidators: map[string]db.ValidatorFunc{}}

	var (
		err error
		vFn db.ValidatorFunc
	)
	_, _ = err, vFn
	vFnMap := map[string]db.ValidatorFunc{}
	_ = vFnMap

	vrhRules := v.RulesValidationRuleHandler
	rulesRules := map[string]string{
		"ves.io.schema.rules.message.required":             "true",
		"ves.io.schema.rules.repeated.max_items":           "4",
		"ves.io.schema.rules.repeated.unique":              "true",
		"ves.io.schema.rules.repeated.unique_threat_level": "true",
	}
	vFn, err = vrhRules(rulesRules)
	if err != nil {
		errMsg := fmt.Sprintf("ValidationRuleHandler for MaliciousUserMitigationType.rules: %s", err)
		panic(errMsg)
	}
	v.FldValidators["rules"] = vFn

	return v
}()

func MaliciousUserMitigationTypeValidator() db.Validator {
	return DefaultMaliciousUserMitigationTypeValidator
}

// augmented methods on protoc/std generated struct

func (m *MaliciousUserThreatLevel) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *MaliciousUserThreatLevel) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *MaliciousUserThreatLevel) DeepCopy() *MaliciousUserThreatLevel {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &MaliciousUserThreatLevel{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *MaliciousUserThreatLevel) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *MaliciousUserThreatLevel) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return MaliciousUserThreatLevelValidator().Validate(ctx, m, opts...)
}

type ValidateMaliciousUserThreatLevel struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateMaliciousUserThreatLevel) ThreatLevelValidationRuleHandler(rules map[string]string) (db.ValidatorFunc, error) {
	validatorFn, err := db.NewMessageValidationRuleHandler(rules)
	if err != nil {
		return nil, errors.Wrap(err, "ValidationRuleHandler for threat_level")
	}
	return validatorFn, nil
}

func (v *ValidateMaliciousUserThreatLevel) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*MaliciousUserThreatLevel)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *MaliciousUserThreatLevel got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	if fv, exists := v.FldValidators["threat_level"]; exists {
		val := m.GetThreatLevel()
		vOpts := append(opts,
			db.WithValidateField("threat_level"),
		)
		if err := fv(ctx, val, vOpts...); err != nil {
			return err
		}
	}

	switch m.GetThreatLevel().(type) {
	case *MaliciousUserThreatLevel_Low:
		if fv, exists := v.FldValidators["threat_level.low"]; exists {
			val := m.GetThreatLevel().(*MaliciousUserThreatLevel_Low).Low
			vOpts := append(opts,
				db.WithValidateField("threat_level"),
				db.WithValidateField("low"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *MaliciousUserThreatLevel_Medium:
		if fv, exists := v.FldValidators["threat_level.medium"]; exists {
			val := m.GetThreatLevel().(*MaliciousUserThreatLevel_Medium).Medium
			vOpts := append(opts,
				db.WithValidateField("threat_level"),
				db.WithValidateField("medium"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}
	case *MaliciousUserThreatLevel_High:
		if fv, exists := v.FldValidators["threat_level.high"]; exists {
			val := m.GetThreatLevel().(*MaliciousUserThreatLevel_High).High
			vOpts := append(opts,
				db.WithValidateField("threat_level"),
				db.WithValidateField("high"),
			)
			if err := fv(ctx, val, vOpts...); err != nil {
				return err
			}
		}

	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultMaliciousUserThreatLevelValidator = func() *ValidateMaliciousUserThreatLevel {
	v := &ValidateMaliciousUserThreatLevel{FldValidators: map[string]db.ValidatorFunc{}}

	var (
		err error
		vFn db.ValidatorFunc
	)
	_, _ = err, vFn
	vFnMap := map[string]db.ValidatorFunc{}
	_ = vFnMap

	vrhThreatLevel := v.ThreatLevelValidationRuleHandler
	rulesThreatLevel := map[string]string{
		"ves.io.schema.rules.message.required_oneof": "true",
	}
	vFn, err = vrhThreatLevel(rulesThreatLevel)
	if err != nil {
		errMsg := fmt.Sprintf("ValidationRuleHandler for MaliciousUserThreatLevel.threat_level: %s", err)
		panic(errMsg)
	}
	v.FldValidators["threat_level"] = vFn

	return v
}()

func MaliciousUserThreatLevelValidator() db.Validator {
	return DefaultMaliciousUserThreatLevelValidator
}

// augmented methods on protoc/std generated struct

func (m *ReplaceSpecType) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *ReplaceSpecType) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *ReplaceSpecType) DeepCopy() *ReplaceSpecType {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &ReplaceSpecType{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *ReplaceSpecType) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *ReplaceSpecType) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return ReplaceSpecTypeValidator().Validate(ctx, m, opts...)
}

type ValidateReplaceSpecType struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateReplaceSpecType) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*ReplaceSpecType)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *ReplaceSpecType got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	if fv, exists := v.FldValidators["mitigation_type"]; exists {

		vOpts := append(opts, db.WithValidateField("mitigation_type"))
		if err := fv(ctx, m.GetMitigationType(), vOpts...); err != nil {
			return err
		}

	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultReplaceSpecTypeValidator = func() *ValidateReplaceSpecType {
	v := &ValidateReplaceSpecType{FldValidators: map[string]db.ValidatorFunc{}}

	v.FldValidators["mitigation_type"] = MaliciousUserMitigationTypeValidator().Validate

	return v
}()

func ReplaceSpecTypeValidator() db.Validator {
	return DefaultReplaceSpecTypeValidator
}

func (m *CreateSpecType) FromGlobalSpecType(f *GlobalSpecType) {
	if f == nil {
		return
	}
	m.MitigationType = f.GetMitigationType()
}

func (m *CreateSpecType) ToGlobalSpecType(f *GlobalSpecType) {
	m1 := m.DeepCopy()
	_ = m1
	if f == nil {
		return
	}
	f.MitigationType = m1.MitigationType
}

func (m *GetSpecType) FromGlobalSpecType(f *GlobalSpecType) {
	if f == nil {
		return
	}
	m.MitigationType = f.GetMitigationType()
}

func (m *GetSpecType) ToGlobalSpecType(f *GlobalSpecType) {
	m1 := m.DeepCopy()
	_ = m1
	if f == nil {
		return
	}
	f.MitigationType = m1.MitigationType
}

func (m *ReplaceSpecType) FromGlobalSpecType(f *GlobalSpecType) {
	if f == nil {
		return
	}
	m.MitigationType = f.GetMitigationType()
}

func (m *ReplaceSpecType) ToGlobalSpecType(f *GlobalSpecType) {
	m1 := m.DeepCopy()
	_ = m1
	if f == nil {
		return
	}
	f.MitigationType = m1.MitigationType
}
