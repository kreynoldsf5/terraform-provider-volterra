//
// Copyright (c) 2018 Volterra, Inc. All rights reserved.
// Code generated by ves-gen-schema-go. DO NOT EDIT.
//
package user

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

func (m *LastLoginUpdateRequest) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *LastLoginUpdateRequest) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *LastLoginUpdateRequest) DeepCopy() *LastLoginUpdateRequest {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &LastLoginUpdateRequest{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *LastLoginUpdateRequest) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *LastLoginUpdateRequest) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return LastLoginUpdateRequestValidator().Validate(ctx, m, opts...)
}

type ValidateLastLoginUpdateRequest struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateLastLoginUpdateRequest) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*LastLoginUpdateRequest)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *LastLoginUpdateRequest got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	if fv, exists := v.FldValidators["last_login_timestamp"]; exists {

		vOpts := append(opts, db.WithValidateField("last_login_timestamp"))
		if err := fv(ctx, m.GetLastLoginTimestamp(), vOpts...); err != nil {
			return err
		}

	}

	if fv, exists := v.FldValidators["tenant"]; exists {

		vOpts := append(opts, db.WithValidateField("tenant"))
		if err := fv(ctx, m.GetTenant(), vOpts...); err != nil {
			return err
		}

	}

	if fv, exists := v.FldValidators["user"]; exists {

		vOpts := append(opts, db.WithValidateField("user"))
		if err := fv(ctx, m.GetUser(), vOpts...); err != nil {
			return err
		}

	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultLastLoginUpdateRequestValidator = func() *ValidateLastLoginUpdateRequest {
	v := &ValidateLastLoginUpdateRequest{FldValidators: map[string]db.ValidatorFunc{}}

	return v
}()

func LastLoginUpdateRequestValidator() db.Validator {
	return DefaultLastLoginUpdateRequestValidator
}

// augmented methods on protoc/std generated struct

func (m *LastLoginUpdateResponse) ToJSON() (string, error) {
	return codec.ToJSON(m)
}

func (m *LastLoginUpdateResponse) ToYAML() (string, error) {
	return codec.ToYAML(m)
}

func (m *LastLoginUpdateResponse) DeepCopy() *LastLoginUpdateResponse {
	if m == nil {
		return nil
	}
	ser, err := m.Marshal()
	if err != nil {
		return nil
	}
	c := &LastLoginUpdateResponse{}
	err = c.Unmarshal(ser)
	if err != nil {
		return nil
	}
	return c
}

func (m *LastLoginUpdateResponse) DeepCopyProto() proto.Message {
	if m == nil {
		return nil
	}
	return m.DeepCopy()
}

func (m *LastLoginUpdateResponse) Validate(ctx context.Context, opts ...db.ValidateOpt) error {
	return LastLoginUpdateResponseValidator().Validate(ctx, m, opts...)
}

type ValidateLastLoginUpdateResponse struct {
	FldValidators map[string]db.ValidatorFunc
}

func (v *ValidateLastLoginUpdateResponse) Validate(ctx context.Context, pm interface{}, opts ...db.ValidateOpt) error {
	m, ok := pm.(*LastLoginUpdateResponse)
	if !ok {
		switch t := pm.(type) {
		case nil:
			return nil
		default:
			return fmt.Errorf("Expected type *LastLoginUpdateResponse got type %s", t)
		}
	}
	if m == nil {
		return nil
	}

	return nil
}

// Well-known symbol for default validator implementation
var DefaultLastLoginUpdateResponseValidator = func() *ValidateLastLoginUpdateResponse {
	v := &ValidateLastLoginUpdateResponse{FldValidators: map[string]db.ValidatorFunc{}}

	return v
}()

func LastLoginUpdateResponseValidator() db.Validator {
	return DefaultLastLoginUpdateResponseValidator
}
