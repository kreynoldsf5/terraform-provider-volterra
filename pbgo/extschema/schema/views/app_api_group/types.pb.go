// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: ves.io/schema/views/app_api_group/types.proto

package app_api_group

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	golang_proto "github.com/golang/protobuf/proto"
	_ "github.com/volterraedge/terraform-provider-volterra/pbgo/extschema/schema"
	api_group_element "github.com/volterraedge/terraform-provider-volterra/pbgo/extschema/schema/api_group_element"
	views "github.com/volterraedge/terraform-provider-volterra/pbgo/extschema/schema/views"
	io "io"
	math "math"
	math_bits "math/bits"
	reflect "reflect"
	strings "strings"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = golang_proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// GlobalSpecType
//
// x-displayName: "Specification"
// Shape of app_api_group in the storage backend.
type GlobalSpecType struct {
	// elements
	//
	// x-displayName: "API Group Elements"
	// x-required
	// List of API group elements with methods and path regex for matching requests.
	Elements []*api_group_element.GlobalSpecType `protobuf:"bytes,1,rep,name=elements,proto3" json:"elements,omitempty"`
	// view_internal
	//
	// x-displayName: "View Internal"
	// Reference to view internal object.
	ViewInternal *views.ObjectRefType `protobuf:"bytes,1000,opt,name=view_internal,json=viewInternal,proto3" json:"view_internal,omitempty"`
}

func (m *GlobalSpecType) Reset()      { *m = GlobalSpecType{} }
func (*GlobalSpecType) ProtoMessage() {}
func (*GlobalSpecType) Descriptor() ([]byte, []int) {
	return fileDescriptor_64d1d0b57abb1bf6, []int{0}
}
func (m *GlobalSpecType) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *GlobalSpecType) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *GlobalSpecType) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GlobalSpecType.Merge(m, src)
}
func (m *GlobalSpecType) XXX_Size() int {
	return m.Size()
}
func (m *GlobalSpecType) XXX_DiscardUnknown() {
	xxx_messageInfo_GlobalSpecType.DiscardUnknown(m)
}

var xxx_messageInfo_GlobalSpecType proto.InternalMessageInfo

func (m *GlobalSpecType) GetElements() []*api_group_element.GlobalSpecType {
	if m != nil {
		return m.Elements
	}
	return nil
}

func (m *GlobalSpecType) GetViewInternal() *views.ObjectRefType {
	if m != nil {
		return m.ViewInternal
	}
	return nil
}

// Create app api group
//
// x-displayName: "Create API Group"
// Create app_api_group creates a new object in the storage backend for metadata.namespace.
type CreateSpecType struct {
	Elements []*api_group_element.GlobalSpecType `protobuf:"bytes,1,rep,name=elements,proto3" json:"elements,omitempty"`
}

func (m *CreateSpecType) Reset()      { *m = CreateSpecType{} }
func (*CreateSpecType) ProtoMessage() {}
func (*CreateSpecType) Descriptor() ([]byte, []int) {
	return fileDescriptor_64d1d0b57abb1bf6, []int{1}
}
func (m *CreateSpecType) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *CreateSpecType) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *CreateSpecType) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateSpecType.Merge(m, src)
}
func (m *CreateSpecType) XXX_Size() int {
	return m.Size()
}
func (m *CreateSpecType) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateSpecType.DiscardUnknown(m)
}

var xxx_messageInfo_CreateSpecType proto.InternalMessageInfo

func (m *CreateSpecType) GetElements() []*api_group_element.GlobalSpecType {
	if m != nil {
		return m.Elements
	}
	return nil
}

// Replace app api group
//
// x-displayName: "Replace API Group"
// Replace app_api_group replaces an existing object in the storage backend for metadata.namespace.
type ReplaceSpecType struct {
	Elements []*api_group_element.GlobalSpecType `protobuf:"bytes,1,rep,name=elements,proto3" json:"elements,omitempty"`
}

func (m *ReplaceSpecType) Reset()      { *m = ReplaceSpecType{} }
func (*ReplaceSpecType) ProtoMessage() {}
func (*ReplaceSpecType) Descriptor() ([]byte, []int) {
	return fileDescriptor_64d1d0b57abb1bf6, []int{2}
}
func (m *ReplaceSpecType) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ReplaceSpecType) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *ReplaceSpecType) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ReplaceSpecType.Merge(m, src)
}
func (m *ReplaceSpecType) XXX_Size() int {
	return m.Size()
}
func (m *ReplaceSpecType) XXX_DiscardUnknown() {
	xxx_messageInfo_ReplaceSpecType.DiscardUnknown(m)
}

var xxx_messageInfo_ReplaceSpecType proto.InternalMessageInfo

func (m *ReplaceSpecType) GetElements() []*api_group_element.GlobalSpecType {
	if m != nil {
		return m.Elements
	}
	return nil
}

// Get app api group
//
// x-displayName: "Get API Group"
// Get app_api_group reads a given object from storage backend for metadata.namespace.
type GetSpecType struct {
	Elements []*api_group_element.GlobalSpecType `protobuf:"bytes,1,rep,name=elements,proto3" json:"elements,omitempty"`
}

func (m *GetSpecType) Reset()      { *m = GetSpecType{} }
func (*GetSpecType) ProtoMessage() {}
func (*GetSpecType) Descriptor() ([]byte, []int) {
	return fileDescriptor_64d1d0b57abb1bf6, []int{3}
}
func (m *GetSpecType) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *GetSpecType) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *GetSpecType) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetSpecType.Merge(m, src)
}
func (m *GetSpecType) XXX_Size() int {
	return m.Size()
}
func (m *GetSpecType) XXX_DiscardUnknown() {
	xxx_messageInfo_GetSpecType.DiscardUnknown(m)
}

var xxx_messageInfo_GetSpecType proto.InternalMessageInfo

func (m *GetSpecType) GetElements() []*api_group_element.GlobalSpecType {
	if m != nil {
		return m.Elements
	}
	return nil
}

func init() {
	proto.RegisterType((*GlobalSpecType)(nil), "ves.io.schema.views.app_api_group.GlobalSpecType")
	golang_proto.RegisterType((*GlobalSpecType)(nil), "ves.io.schema.views.app_api_group.GlobalSpecType")
	proto.RegisterType((*CreateSpecType)(nil), "ves.io.schema.views.app_api_group.CreateSpecType")
	golang_proto.RegisterType((*CreateSpecType)(nil), "ves.io.schema.views.app_api_group.CreateSpecType")
	proto.RegisterType((*ReplaceSpecType)(nil), "ves.io.schema.views.app_api_group.ReplaceSpecType")
	golang_proto.RegisterType((*ReplaceSpecType)(nil), "ves.io.schema.views.app_api_group.ReplaceSpecType")
	proto.RegisterType((*GetSpecType)(nil), "ves.io.schema.views.app_api_group.GetSpecType")
	golang_proto.RegisterType((*GetSpecType)(nil), "ves.io.schema.views.app_api_group.GetSpecType")
}

func init() {
	proto.RegisterFile("ves.io/schema/views/app_api_group/types.proto", fileDescriptor_64d1d0b57abb1bf6)
}
func init() {
	golang_proto.RegisterFile("ves.io/schema/views/app_api_group/types.proto", fileDescriptor_64d1d0b57abb1bf6)
}

var fileDescriptor_64d1d0b57abb1bf6 = []byte{
	// 457 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xbc, 0x53, 0x31, 0x6f, 0x13, 0x31,
	0x18, 0xbd, 0x8f, 0xa0, 0xb6, 0xba, 0x40, 0x29, 0x11, 0x43, 0x09, 0xc8, 0x84, 0x4c, 0x95, 0x50,
	0x6c, 0xa9, 0x6c, 0x0c, 0x0c, 0x65, 0xa8, 0x80, 0x01, 0x29, 0x20, 0x81, 0x18, 0x88, 0x7c, 0xd7,
	0x2f, 0x57, 0xc3, 0x25, 0xb6, 0x7c, 0xce, 0x95, 0x0e, 0x48, 0xfc, 0x04, 0x84, 0xc4, 0x7f, 0x40,
	0xfc, 0x04, 0x58, 0x3a, 0x22, 0xa6, 0x8c, 0x19, 0x89, 0x6f, 0x39, 0xb6, 0xfe, 0x04, 0x84, 0x73,
	0x0d, 0x71, 0x5b, 0x26, 0xa4, 0x6c, 0xb6, 0xdf, 0xfb, 0xde, 0xf3, 0x7b, 0xe7, 0x0b, 0x3b, 0x39,
	0x66, 0x54, 0x48, 0x96, 0xc5, 0xfb, 0x38, 0xe0, 0x2c, 0x17, 0x78, 0x90, 0x31, 0xae, 0x54, 0x8f,
	0x2b, 0xd1, 0x4b, 0xb4, 0x1c, 0x29, 0x66, 0x0e, 0x15, 0x66, 0x54, 0x69, 0x69, 0x64, 0xe3, 0xf6,
	0x8c, 0x4e, 0x67, 0x74, 0xea, 0xe8, 0xd4, 0xa3, 0x37, 0x3b, 0x89, 0x30, 0xfb, 0xa3, 0x88, 0xc6,
	0x72, 0xc0, 0x12, 0x99, 0x48, 0xe6, 0x26, 0xa3, 0x51, 0xdf, 0xed, 0xdc, 0xc6, 0xad, 0x66, 0x8a,
	0xcd, 0x3b, 0xfe, 0x05, 0xe6, 0x3a, 0x3d, 0x4c, 0x71, 0x80, 0x43, 0xb3, 0x68, 0xdf, 0xbc, 0xe1,
	0x93, 0xa5, 0x32, 0x42, 0x0e, 0x4f, 0xc0, 0xeb, 0x3e, 0xb8, 0x38, 0x77, 0xf3, 0x54, 0x4a, 0x9e,
	0x8a, 0x3d, 0x6e, 0xb0, 0x42, 0x5b, 0x67, 0x3b, 0xe8, 0xf9, 0xd2, 0xb7, 0xce, 0x6b, 0x69, 0xc1,
	0xa0, 0x3d, 0x86, 0x70, 0x7d, 0x37, 0x95, 0x11, 0x4f, 0x9f, 0x2a, 0x8c, 0x9f, 0x1d, 0x2a, 0x6c,
	0xbc, 0x08, 0xd7, 0xaa, 0x08, 0xd9, 0x26, 0xb4, 0x6a, 0x5b, 0xf5, 0x6d, 0x46, 0xfd, 0xf6, 0xce,
	0x64, 0xa5, 0xbe, 0xc4, 0x4e, 0xfd, 0xeb, 0xaf, 0xa3, 0xda, 0xca, 0x47, 0xa8, 0x6d, 0x94, 0xab,
	0xdd, 0xb9, 0x5a, 0xe3, 0x55, 0x78, 0xd9, 0xdd, 0x51, 0x0c, 0x0d, 0xea, 0x21, 0x4f, 0x37, 0xcb,
	0xd5, 0x16, 0x6c, 0xd5, 0xb7, 0xdb, 0xf4, 0xbc, 0xaf, 0xf3, 0x24, 0x7a, 0x8d, 0xb1, 0xe9, 0x62,
	0xdf, 0x49, 0x5e, 0xfb, 0xf2, 0xce, 0x1f, 0x2e, 0xbf, 0x01, 0x74, 0x2f, 0xfd, 0x39, 0x7a, 0x58,
	0x9d, 0x3c, 0xba, 0xb8, 0x76, 0x61, 0xa3, 0xd6, 0xce, 0xc3, 0xf5, 0x07, 0x1a, 0xb9, 0xc1, 0x79,
	0xa2, 0xc7, 0xff, 0x9d, 0xe8, 0x6f, 0x88, 0x7b, 0x57, 0x7f, 0xdc, 0x3f, 0xd5, 0x58, 0xe5, 0x7b,
	0x10, 0x5e, 0xe9, 0xa2, 0x4a, 0x79, 0xbc, 0x6c, 0xe3, 0x2c, 0xac, 0xef, 0xa2, 0x59, 0xae, 0xe9,
	0xce, 0x27, 0x18, 0x4f, 0x49, 0x30, 0x99, 0x92, 0xe0, 0x78, 0x4a, 0xe0, 0xbd, 0x25, 0xf0, 0xd9,
	0x12, 0xf8, 0x6e, 0x09, 0x8c, 0x2d, 0x81, 0x89, 0x25, 0xf0, 0xd3, 0x12, 0x28, 0x2d, 0x09, 0x8e,
	0x2d, 0x81, 0x0f, 0x05, 0x09, 0x8e, 0x0a, 0x02, 0xe3, 0x82, 0x04, 0x93, 0x82, 0x04, 0x2f, 0x9f,
	0x27, 0x52, 0xbd, 0x49, 0x68, 0x2e, 0x53, 0x83, 0x5a, 0x73, 0x3a, 0xca, 0x98, 0x5b, 0xf4, 0xa5,
	0x1e, 0x74, 0x94, 0x96, 0xb9, 0xd8, 0x43, 0xdd, 0x39, 0x81, 0x99, 0x8a, 0x12, 0xc9, 0xf0, 0xad,
	0xa9, 0xde, 0xf1, 0xbf, 0x7f, 0xfa, 0x68, 0xc5, 0xbd, 0xeb, 0xbb, 0xbf, 0x03, 0x00, 0x00, 0xff,
	0xff, 0x7c, 0x81, 0xdc, 0xa8, 0x20, 0x04, 0x00, 0x00,
}

func (this *GlobalSpecType) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*GlobalSpecType)
	if !ok {
		that2, ok := that.(GlobalSpecType)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if len(this.Elements) != len(that1.Elements) {
		return false
	}
	for i := range this.Elements {
		if !this.Elements[i].Equal(that1.Elements[i]) {
			return false
		}
	}
	if !this.ViewInternal.Equal(that1.ViewInternal) {
		return false
	}
	return true
}
func (this *CreateSpecType) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*CreateSpecType)
	if !ok {
		that2, ok := that.(CreateSpecType)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if len(this.Elements) != len(that1.Elements) {
		return false
	}
	for i := range this.Elements {
		if !this.Elements[i].Equal(that1.Elements[i]) {
			return false
		}
	}
	return true
}
func (this *ReplaceSpecType) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*ReplaceSpecType)
	if !ok {
		that2, ok := that.(ReplaceSpecType)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if len(this.Elements) != len(that1.Elements) {
		return false
	}
	for i := range this.Elements {
		if !this.Elements[i].Equal(that1.Elements[i]) {
			return false
		}
	}
	return true
}
func (this *GetSpecType) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*GetSpecType)
	if !ok {
		that2, ok := that.(GetSpecType)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if len(this.Elements) != len(that1.Elements) {
		return false
	}
	for i := range this.Elements {
		if !this.Elements[i].Equal(that1.Elements[i]) {
			return false
		}
	}
	return true
}
func (this *GlobalSpecType) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 6)
	s = append(s, "&app_api_group.GlobalSpecType{")
	if this.Elements != nil {
		s = append(s, "Elements: "+fmt.Sprintf("%#v", this.Elements)+",\n")
	}
	if this.ViewInternal != nil {
		s = append(s, "ViewInternal: "+fmt.Sprintf("%#v", this.ViewInternal)+",\n")
	}
	s = append(s, "}")
	return strings.Join(s, "")
}
func (this *CreateSpecType) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 5)
	s = append(s, "&app_api_group.CreateSpecType{")
	if this.Elements != nil {
		s = append(s, "Elements: "+fmt.Sprintf("%#v", this.Elements)+",\n")
	}
	s = append(s, "}")
	return strings.Join(s, "")
}
func (this *ReplaceSpecType) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 5)
	s = append(s, "&app_api_group.ReplaceSpecType{")
	if this.Elements != nil {
		s = append(s, "Elements: "+fmt.Sprintf("%#v", this.Elements)+",\n")
	}
	s = append(s, "}")
	return strings.Join(s, "")
}
func (this *GetSpecType) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 5)
	s = append(s, "&app_api_group.GetSpecType{")
	if this.Elements != nil {
		s = append(s, "Elements: "+fmt.Sprintf("%#v", this.Elements)+",\n")
	}
	s = append(s, "}")
	return strings.Join(s, "")
}
func valueToGoStringTypes(v interface{}, typ string) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("func(v %v) *%v { return &v } ( %#v )", typ, typ, pv)
}
func (m *GlobalSpecType) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *GlobalSpecType) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *GlobalSpecType) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.ViewInternal != nil {
		{
			size, err := m.ViewInternal.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintTypes(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x3e
		i--
		dAtA[i] = 0xc2
	}
	if len(m.Elements) > 0 {
		for iNdEx := len(m.Elements) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.Elements[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintTypes(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func (m *CreateSpecType) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *CreateSpecType) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *CreateSpecType) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Elements) > 0 {
		for iNdEx := len(m.Elements) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.Elements[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintTypes(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func (m *ReplaceSpecType) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ReplaceSpecType) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ReplaceSpecType) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Elements) > 0 {
		for iNdEx := len(m.Elements) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.Elements[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintTypes(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func (m *GetSpecType) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *GetSpecType) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *GetSpecType) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Elements) > 0 {
		for iNdEx := len(m.Elements) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.Elements[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintTypes(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func encodeVarintTypes(dAtA []byte, offset int, v uint64) int {
	offset -= sovTypes(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *GlobalSpecType) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.Elements) > 0 {
		for _, e := range m.Elements {
			l = e.Size()
			n += 1 + l + sovTypes(uint64(l))
		}
	}
	if m.ViewInternal != nil {
		l = m.ViewInternal.Size()
		n += 2 + l + sovTypes(uint64(l))
	}
	return n
}

func (m *CreateSpecType) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.Elements) > 0 {
		for _, e := range m.Elements {
			l = e.Size()
			n += 1 + l + sovTypes(uint64(l))
		}
	}
	return n
}

func (m *ReplaceSpecType) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.Elements) > 0 {
		for _, e := range m.Elements {
			l = e.Size()
			n += 1 + l + sovTypes(uint64(l))
		}
	}
	return n
}

func (m *GetSpecType) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.Elements) > 0 {
		for _, e := range m.Elements {
			l = e.Size()
			n += 1 + l + sovTypes(uint64(l))
		}
	}
	return n
}

func sovTypes(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozTypes(x uint64) (n int) {
	return sovTypes(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *GlobalSpecType) String() string {
	if this == nil {
		return "nil"
	}
	repeatedStringForElements := "[]*GlobalSpecType{"
	for _, f := range this.Elements {
		repeatedStringForElements += strings.Replace(fmt.Sprintf("%v", f), "GlobalSpecType", "api_group_element.GlobalSpecType", 1) + ","
	}
	repeatedStringForElements += "}"
	s := strings.Join([]string{`&GlobalSpecType{`,
		`Elements:` + repeatedStringForElements + `,`,
		`ViewInternal:` + strings.Replace(fmt.Sprintf("%v", this.ViewInternal), "ObjectRefType", "views.ObjectRefType", 1) + `,`,
		`}`,
	}, "")
	return s
}
func (this *CreateSpecType) String() string {
	if this == nil {
		return "nil"
	}
	repeatedStringForElements := "[]*GlobalSpecType{"
	for _, f := range this.Elements {
		repeatedStringForElements += strings.Replace(fmt.Sprintf("%v", f), "GlobalSpecType", "api_group_element.GlobalSpecType", 1) + ","
	}
	repeatedStringForElements += "}"
	s := strings.Join([]string{`&CreateSpecType{`,
		`Elements:` + repeatedStringForElements + `,`,
		`}`,
	}, "")
	return s
}
func (this *ReplaceSpecType) String() string {
	if this == nil {
		return "nil"
	}
	repeatedStringForElements := "[]*GlobalSpecType{"
	for _, f := range this.Elements {
		repeatedStringForElements += strings.Replace(fmt.Sprintf("%v", f), "GlobalSpecType", "api_group_element.GlobalSpecType", 1) + ","
	}
	repeatedStringForElements += "}"
	s := strings.Join([]string{`&ReplaceSpecType{`,
		`Elements:` + repeatedStringForElements + `,`,
		`}`,
	}, "")
	return s
}
func (this *GetSpecType) String() string {
	if this == nil {
		return "nil"
	}
	repeatedStringForElements := "[]*GlobalSpecType{"
	for _, f := range this.Elements {
		repeatedStringForElements += strings.Replace(fmt.Sprintf("%v", f), "GlobalSpecType", "api_group_element.GlobalSpecType", 1) + ","
	}
	repeatedStringForElements += "}"
	s := strings.Join([]string{`&GetSpecType{`,
		`Elements:` + repeatedStringForElements + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringTypes(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *GlobalSpecType) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTypes
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: GlobalSpecType: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: GlobalSpecType: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Elements", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTypes
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Elements = append(m.Elements, &api_group_element.GlobalSpecType{})
			if err := m.Elements[len(m.Elements)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 1000:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ViewInternal", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTypes
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.ViewInternal == nil {
				m.ViewInternal = &views.ObjectRefType{}
			}
			if err := m.ViewInternal.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTypes(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTypes
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthTypes
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *CreateSpecType) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTypes
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: CreateSpecType: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: CreateSpecType: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Elements", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTypes
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Elements = append(m.Elements, &api_group_element.GlobalSpecType{})
			if err := m.Elements[len(m.Elements)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTypes(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTypes
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthTypes
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ReplaceSpecType) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTypes
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ReplaceSpecType: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ReplaceSpecType: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Elements", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTypes
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Elements = append(m.Elements, &api_group_element.GlobalSpecType{})
			if err := m.Elements[len(m.Elements)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTypes(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTypes
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthTypes
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *GetSpecType) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTypes
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: GetSpecType: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: GetSpecType: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Elements", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTypes
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Elements = append(m.Elements, &api_group_element.GlobalSpecType{})
			if err := m.Elements[len(m.Elements)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTypes(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTypes
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthTypes
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipTypes(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowTypes
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthTypes
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupTypes
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthTypes
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthTypes        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowTypes          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupTypes = fmt.Errorf("proto: unexpected end of group")
)
