//
// Copyright (c) 2022 F5, Inc. All rights reserved.
// Code generated by ves-gen-schema-go. DO NOT EDIT.
//
package scim

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

func (m *ServiceProviderConfigResponse) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *ServiceProviderConfigResponse) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *ServiceProviderConfigResponse) DeepCopy() *ServiceProviderConfigResponse {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &ServiceProviderConfigResponse{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *ServiceProviderConfigResponse) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *ServiceProviderConfigResponse) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return ServiceProviderConfigResponseValidator().Validate(ctx, m, opts...)
}

type ValidateServiceProviderConfigResponse struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateServiceProviderConfigResponse) SchemasValidationRuleHandler(rules map[string]string) (db.ValidatorFunc, error) {

	itemRules := db.GetRepStringItemRules(rules)
	itemValFn, err := db.NewStringValidationRuleHandler(itemRules)
	if err != nil {
		return nil, errors.Wrap(err, "Item ValidationRuleHandler for schemas")
	}
	itemsValidatorFn := func(ctx context.Context, elems []string, opts ...db.ValidateOpt) error {
		for i, el := range elems {
			if err := itemValFn(ctx, el, opts...); err != nil {
				return errors.Wrap(err, fmt.Sprintf("element %d", i))
			}
		}
		return nil
	}
	repValFn, err := db.NewRepeatedValidationRuleHandler(rules)
	if err != nil {
		return nil, errors.Wrap(err, "Repeated ValidationRuleHandler for schemas")
	}

	validatorFn := func(ctx context.Context, val interface{}, opts ...db.ValidateOpt) error {
		elems, ok := val.([]string)
		if !ok {
			return fmt.Errorf("Repeated validation expected []string, got %T", val)
		}
		l := []string{}
		for _, elem := range elems {
			strVal := fmt.Sprintf("%v", elem)
			l = append(l, strVal)
		}
		if err := repValFn(ctx, l, opts...); err != nil {
			return errors.Wrap(err, "repeated schemas")
		}
		if err := itemsValidatorFn(ctx, elems, opts...); err != nil {
			return errors.Wrap(err, "items schemas")
		}
		return nil
	}

	return validatorFn, nil
}

func (v *ValidateServiceProviderConfigResponse) DocumentationUriValidationRuleHandler(rules map[string]string) (db.ValidatorFunc, error) {

	validatorFn, err := db.NewStringValidationRuleHandler(rules)
	if err != nil {
		return nil, errors.Wrap(err, "ValidationRuleHandler for documentationUri")
	}

	return validatorFn, nil
}

func (v *ValidateServiceProviderConfigResponse) PatchValidationRuleHandler(rules map[string]string) (db.ValidatorFunc, error) {

	reqdValidatorFn, err := db.NewMessageValidationRuleHandler(rules)
	if err != nil {
		return nil, errors.Wrap(err, "MessageValidationRuleHandler for patch")
	}
	validatorFn := func(ctx context.Context, val interface{}, opts ...db.ValidateOpt) error {
		if err := reqdValidatorFn(ctx, val, opts...); err != nil {
			return err
		}

		if err := SupportValidator().Validate(ctx, val, opts...); err != nil {
			return err
		}

		return nil
	}

	return validatorFn, nil
}

func (v *ValidateServiceProviderConfigResponse) BulkValidationRuleHandler(rules map[string]string) (db.ValidatorFunc, error) {

	reqdValidatorFn, err := db.NewMessageValidationRuleHandler(rules)
	if err != nil {
		return nil, errors.Wrap(err, "MessageValidationRuleHandler for bulk")
	}
	validatorFn := func(ctx context.Context, val interface{}, opts ...db.ValidateOpt) error {
		if err := reqdValidatorFn(ctx, val, opts...); err != nil {
			return err
		}

		if err := SupportValidator().Validate(ctx, val, opts...); err != nil {
			return err
		}

		return nil
	}

	return validatorFn, nil
}

func (v *ValidateServiceProviderConfigResponse) FilterValidationRuleHandler(rules map[string]string) (db.ValidatorFunc, error) {

	reqdValidatorFn, err := db.NewMessageValidationRuleHandler(rules)
	if err != nil {
		return nil, errors.Wrap(err, "MessageValidationRuleHandler for filter")
	}
	validatorFn := func(ctx context.Context, val interface{}, opts ...db.ValidateOpt) error {
		if err := reqdValidatorFn(ctx, val, opts...); err != nil {
			return err
		}

		if err := FilterValidator().Validate(ctx, val, opts...); err != nil {
			return err
		}

		return nil
	}

	return validatorFn, nil
}

func (v *ValidateServiceProviderConfigResponse) ChangePasswordValidationRuleHandler(rules map[string]string) (db.ValidatorFunc, error) {

	reqdValidatorFn, err := db.NewMessageValidationRuleHandler(rules)
	if err != nil {
		return nil, errors.Wrap(err, "MessageValidationRuleHandler for changePassword")
	}
	validatorFn := func(ctx context.Context, val interface{}, opts ...db.ValidateOpt) error {
		if err := reqdValidatorFn(ctx, val, opts...); err != nil {
			return err
		}

		if err := SupportValidator().Validate(ctx, val, opts...); err != nil {
			return err
		}

		return nil
	}

	return validatorFn, nil
}

func (v *ValidateServiceProviderConfigResponse) SortValidationRuleHandler(rules map[string]string) (db.ValidatorFunc, error) {

	reqdValidatorFn, err := db.NewMessageValidationRuleHandler(rules)
	if err != nil {
		return nil, errors.Wrap(err, "MessageValidationRuleHandler for sort")
	}
	validatorFn := func(ctx context.Context, val interface{}, opts ...db.ValidateOpt) error {
		if err := reqdValidatorFn(ctx, val, opts...); err != nil {
			return err
		}

		if err := SupportValidator().Validate(ctx, val, opts...); err != nil {
			return err
		}

		return nil
	}

	return validatorFn, nil
}

func (v *ValidateServiceProviderConfigResponse) EtagValidationRuleHandler(rules map[string]string) (db.ValidatorFunc, error) {

	reqdValidatorFn, err := db.NewMessageValidationRuleHandler(rules)
	if err != nil {
		return nil, errors.Wrap(err, "MessageValidationRuleHandler for etag")
	}
	validatorFn := func(ctx context.Context, val interface{}, opts ...db.ValidateOpt) error {
		if err := reqdValidatorFn(ctx, val, opts...); err != nil {
			return err
		}

		if err := SupportValidator().Validate(ctx, val, opts...); err != nil {
			return err
		}

		return nil
	}

	return validatorFn, nil
}

func (v *ValidateServiceProviderConfigResponse) AuthenticationSchemesValidationRuleHandler(rules map[string]string) (db.ValidatorFunc, error) {

	itemRules := db.GetRepStringItemRules(rules)
	itemValFn, err := db.NewStringValidationRuleHandler(itemRules)
	if err != nil {
		return nil, errors.Wrap(err, "Item ValidationRuleHandler for authenticationSchemes")
	}
	itemsValidatorFn := func(ctx context.Context, elems []string, opts ...db.ValidateOpt) error {
		for i, el := range elems {
			if err := itemValFn(ctx, el, opts...); err != nil {
				return errors.Wrap(err, fmt.Sprintf("element %d", i))
			}
		}
		return nil
	}
	repValFn, err := db.NewRepeatedValidationRuleHandler(rules)
	if err != nil {
		return nil, errors.Wrap(err, "Repeated ValidationRuleHandler for authenticationSchemes")
	}

	validatorFn := func(ctx context.Context, val interface{}, opts ...db.ValidateOpt) error {
		elems, ok := val.([]string)
		if !ok {
			return fmt.Errorf("Repeated validation expected []string, got %T", val)
		}
		l := []string{}
		for _, elem := range elems {
			strVal := fmt.Sprintf("%v", elem)
			l = append(l, strVal)
		}
		if err := repValFn(ctx, l, opts...); err != nil {
			return errors.Wrap(err, "repeated authenticationSchemes")
		}
		if err := itemsValidatorFn(ctx, elems, opts...); err != nil {
			return errors.Wrap(err, "items authenticationSchemes")
		}
		return nil
	}

	return validatorFn, nil
}

func (v *ValidateServiceProviderConfigResponse) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*ServiceProviderConfigResponse)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *ServiceProviderConfigResponse got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	if fv, exists := v.FldValidators["authenticationSchemes"]; exists {
		vOpts := append(opts, db.WithValidateField("authenticationSchemes"))
		if err := fv(ctx, m.GetAuthenticationSchemes(), vOpts...); err != nil {
			return err
		}

	}

	if fv, exists := v.FldValidators["bulk"]; exists {

		vOpts := append(opts, db.WithValidateField("bulk"))
		if err := fv(ctx, m.GetBulk(), vOpts...); err != nil {
			return err
		}

	}

	if fv, exists := v.FldValidators["changePassword"]; exists {

		vOpts := append(opts, db.WithValidateField("changePassword"))
		if err := fv(ctx, m.GetChangePassword(), vOpts...); err != nil {
			return err
		}

	}

	if fv, exists := v.FldValidators["documentationUri"]; exists {

		vOpts := append(opts, db.WithValidateField("documentationUri"))
		if err := fv(ctx, m.GetDocumentationUri(), vOpts...); err != nil {
			return err
		}

	}

	if fv, exists := v.FldValidators["etag"]; exists {

		vOpts := append(opts, db.WithValidateField("etag"))
		if err := fv(ctx, m.GetEtag(), vOpts...); err != nil {
			return err
		}

	}

	if fv, exists := v.FldValidators["filter"]; exists {

		vOpts := append(opts, db.WithValidateField("filter"))
		if err := fv(ctx, m.GetFilter(), vOpts...); err != nil {
			return err
		}

	}

	if fv, exists := v.FldValidators["patch"]; exists {

		vOpts := append(opts, db.WithValidateField("patch"))
		if err := fv(ctx, m.GetPatch(), vOpts...); err != nil {
			return err
		}

	}

	if fv, exists := v.FldValidators["schemas"]; exists {
		vOpts := append(opts, db.WithValidateField("schemas"))
		if err := fv(ctx, m.GetSchemas(), vOpts...); err != nil {
			return err
		}

	}

	if fv, exists := v.FldValidators["sort"]; exists {

		vOpts := append(opts, db.WithValidateField("sort"))
		if err := fv(ctx, m.GetSort(), vOpts...); err != nil {
			return err
		}

	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultServiceProviderConfigResponseValidator = func() *ValidateServiceProviderConfigResponse {
	v := &ValidateServiceProviderConfigResponse{FldValidators: map[string]db.ValidatorFunc{}}

	var (
		err error
		vFn db.ValidatorFunc
	)
	_, _ = err, vFn
	vFnMap := map[string]db.ValidatorFunc{}
	_ = vFnMap

	vrhSchemas := v.SchemasValidationRuleHandler
	rulesSchemas := map[string]string{
		"ves.io.schema.rules.message.required": "true",
	}
	vFn, err = vrhSchemas(rulesSchemas)
	if err != nil {
		errMsg := fmt.Sprintf("ValidationRuleHandler for ServiceProviderConfigResponse.schemas: %s", err)
		panic(errMsg)
	}
	v.FldValidators["schemas"] = vFn

	vrhDocumentationUri := v.DocumentationUriValidationRuleHandler
	rulesDocumentationUri := map[string]string{
		"ves.io.schema.rules.message.required": "true",
	}
	vFn, err = vrhDocumentationUri(rulesDocumentationUri)
	if err != nil {
		errMsg := fmt.Sprintf("ValidationRuleHandler for ServiceProviderConfigResponse.documentationUri: %s", err)
		panic(errMsg)
	}
	v.FldValidators["documentationUri"] = vFn

	vrhPatch := v.PatchValidationRuleHandler
	rulesPatch := map[string]string{
		"ves.io.schema.rules.message.required": "true",
	}
	vFn, err = vrhPatch(rulesPatch)
	if err != nil {
		errMsg := fmt.Sprintf("ValidationRuleHandler for ServiceProviderConfigResponse.patch: %s", err)
		panic(errMsg)
	}
	v.FldValidators["patch"] = vFn

	vrhBulk := v.BulkValidationRuleHandler
	rulesBulk := map[string]string{
		"ves.io.schema.rules.message.required": "true",
	}
	vFn, err = vrhBulk(rulesBulk)
	if err != nil {
		errMsg := fmt.Sprintf("ValidationRuleHandler for ServiceProviderConfigResponse.bulk: %s", err)
		panic(errMsg)
	}
	v.FldValidators["bulk"] = vFn

	vrhFilter := v.FilterValidationRuleHandler
	rulesFilter := map[string]string{
		"ves.io.schema.rules.message.required": "true",
	}
	vFn, err = vrhFilter(rulesFilter)
	if err != nil {
		errMsg := fmt.Sprintf("ValidationRuleHandler for ServiceProviderConfigResponse.filter: %s", err)
		panic(errMsg)
	}
	v.FldValidators["filter"] = vFn

	vrhChangePassword := v.ChangePasswordValidationRuleHandler
	rulesChangePassword := map[string]string{
		"ves.io.schema.rules.message.required": "true",
	}
	vFn, err = vrhChangePassword(rulesChangePassword)
	if err != nil {
		errMsg := fmt.Sprintf("ValidationRuleHandler for ServiceProviderConfigResponse.changePassword: %s", err)
		panic(errMsg)
	}
	v.FldValidators["changePassword"] = vFn

	vrhSort := v.SortValidationRuleHandler
	rulesSort := map[string]string{
		"ves.io.schema.rules.message.required": "true",
	}
	vFn, err = vrhSort(rulesSort)
	if err != nil {
		errMsg := fmt.Sprintf("ValidationRuleHandler for ServiceProviderConfigResponse.sort: %s", err)
		panic(errMsg)
	}
	v.FldValidators["sort"] = vFn

	vrhEtag := v.EtagValidationRuleHandler
	rulesEtag := map[string]string{
		"ves.io.schema.rules.message.required": "true",
	}
	vFn, err = vrhEtag(rulesEtag)
	if err != nil {
		errMsg := fmt.Sprintf("ValidationRuleHandler for ServiceProviderConfigResponse.etag: %s", err)
		panic(errMsg)
	}
	v.FldValidators["etag"] = vFn

	vrhAuthenticationSchemes := v.AuthenticationSchemesValidationRuleHandler
	rulesAuthenticationSchemes := map[string]string{
		"ves.io.schema.rules.message.required": "true",
	}
	vFn, err = vrhAuthenticationSchemes(rulesAuthenticationSchemes)
	if err != nil {
		errMsg := fmt.Sprintf("ValidationRuleHandler for ServiceProviderConfigResponse.authenticationSchemes: %s", err)
		panic(errMsg)
	}
	v.FldValidators["authenticationSchemes"] = vFn

	return v
}()

func ServiceProviderConfigResponseValidator() db.Validator {
	return DefaultServiceProviderConfigResponseValidator
}
