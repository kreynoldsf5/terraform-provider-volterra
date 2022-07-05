// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: ves.io/schema/vesenv/all_addon_services.proto

package vesenv

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
	reflect "reflect"
	strings "strings"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// AddonServiceChoice enumerates all the well-known addon_service.Objects in a VES environment
type AddonServiceChoice struct {
	// Types that are valid to be assigned to Choice:
	//	*AddonServiceChoice_VesIoVolterraDefault
	//	*AddonServiceChoice_VesIoTenantManagement
	//	*AddonServiceChoice_VesIoScim
	//	*AddonServiceChoice_ShapeBot
	//	*AddonServiceChoice_ShapeRecognize
	//	*AddonServiceChoice_AidataBfdp
	//	*AddonServiceChoice_LilacCdn
	//	*AddonServiceChoice_NginxMgmtSuite
	Choice isAddonServiceChoice_Choice `protobuf_oneof:"choice"`
}

func (m *AddonServiceChoice) Reset()      { *m = AddonServiceChoice{} }
func (*AddonServiceChoice) ProtoMessage() {}
func (*AddonServiceChoice) Descriptor() ([]byte, []int) {
	return fileDescriptor_24b1043c1548ccb0, []int{0}
}
func (m *AddonServiceChoice) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *AddonServiceChoice) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_AddonServiceChoice.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *AddonServiceChoice) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AddonServiceChoice.Merge(m, src)
}
func (m *AddonServiceChoice) XXX_Size() int {
	return m.Size()
}
func (m *AddonServiceChoice) XXX_DiscardUnknown() {
	xxx_messageInfo_AddonServiceChoice.DiscardUnknown(m)
}

var xxx_messageInfo_AddonServiceChoice proto.InternalMessageInfo

type isAddonServiceChoice_Choice interface {
	isAddonServiceChoice_Choice()
	Equal(interface{}) bool
	MarshalTo([]byte) (int, error)
	Size() int
}

type AddonServiceChoice_VesIoVolterraDefault struct {
	VesIoVolterraDefault bool `protobuf:"varint,1,opt,name=ves_io_volterra_default,json=vesIoVolterraDefault,proto3,oneof" json:"ves_io_volterra_default,omitempty"`
}
type AddonServiceChoice_VesIoTenantManagement struct {
	VesIoTenantManagement bool `protobuf:"varint,2,opt,name=ves_io_tenant_management,json=vesIoTenantManagement,proto3,oneof" json:"ves_io_tenant_management,omitempty"`
}
type AddonServiceChoice_VesIoScim struct {
	VesIoScim bool `protobuf:"varint,4,opt,name=ves_io_scim,json=vesIoScim,proto3,oneof" json:"ves_io_scim,omitempty"`
}
type AddonServiceChoice_ShapeBot struct {
	ShapeBot bool `protobuf:"varint,50,opt,name=shape_bot,json=shapeBot,proto3,oneof" json:"shape_bot,omitempty"`
}
type AddonServiceChoice_ShapeRecognize struct {
	ShapeRecognize bool `protobuf:"varint,51,opt,name=shape_recognize,json=shapeRecognize,proto3,oneof" json:"shape_recognize,omitempty"`
}
type AddonServiceChoice_AidataBfdp struct {
	AidataBfdp bool `protobuf:"varint,52,opt,name=aidata_bfdp,json=aidataBfdp,proto3,oneof" json:"aidata_bfdp,omitempty"`
}
type AddonServiceChoice_LilacCdn struct {
	LilacCdn bool `protobuf:"varint,53,opt,name=lilac_cdn,json=lilacCdn,proto3,oneof" json:"lilac_cdn,omitempty"`
}
type AddonServiceChoice_NginxMgmtSuite struct {
	NginxMgmtSuite bool `protobuf:"varint,54,opt,name=nginx_mgmt_suite,json=nginxMgmtSuite,proto3,oneof" json:"nginx_mgmt_suite,omitempty"`
}

func (*AddonServiceChoice_VesIoVolterraDefault) isAddonServiceChoice_Choice()  {}
func (*AddonServiceChoice_VesIoTenantManagement) isAddonServiceChoice_Choice() {}
func (*AddonServiceChoice_VesIoScim) isAddonServiceChoice_Choice()             {}
func (*AddonServiceChoice_ShapeBot) isAddonServiceChoice_Choice()              {}
func (*AddonServiceChoice_ShapeRecognize) isAddonServiceChoice_Choice()        {}
func (*AddonServiceChoice_AidataBfdp) isAddonServiceChoice_Choice()            {}
func (*AddonServiceChoice_LilacCdn) isAddonServiceChoice_Choice()              {}
func (*AddonServiceChoice_NginxMgmtSuite) isAddonServiceChoice_Choice()        {}

func (m *AddonServiceChoice) GetChoice() isAddonServiceChoice_Choice {
	if m != nil {
		return m.Choice
	}
	return nil
}

func (m *AddonServiceChoice) GetVesIoVolterraDefault() bool {
	if x, ok := m.GetChoice().(*AddonServiceChoice_VesIoVolterraDefault); ok {
		return x.VesIoVolterraDefault
	}
	return false
}

func (m *AddonServiceChoice) GetVesIoTenantManagement() bool {
	if x, ok := m.GetChoice().(*AddonServiceChoice_VesIoTenantManagement); ok {
		return x.VesIoTenantManagement
	}
	return false
}

func (m *AddonServiceChoice) GetVesIoScim() bool {
	if x, ok := m.GetChoice().(*AddonServiceChoice_VesIoScim); ok {
		return x.VesIoScim
	}
	return false
}

func (m *AddonServiceChoice) GetShapeBot() bool {
	if x, ok := m.GetChoice().(*AddonServiceChoice_ShapeBot); ok {
		return x.ShapeBot
	}
	return false
}

func (m *AddonServiceChoice) GetShapeRecognize() bool {
	if x, ok := m.GetChoice().(*AddonServiceChoice_ShapeRecognize); ok {
		return x.ShapeRecognize
	}
	return false
}

func (m *AddonServiceChoice) GetAidataBfdp() bool {
	if x, ok := m.GetChoice().(*AddonServiceChoice_AidataBfdp); ok {
		return x.AidataBfdp
	}
	return false
}

func (m *AddonServiceChoice) GetLilacCdn() bool {
	if x, ok := m.GetChoice().(*AddonServiceChoice_LilacCdn); ok {
		return x.LilacCdn
	}
	return false
}

func (m *AddonServiceChoice) GetNginxMgmtSuite() bool {
	if x, ok := m.GetChoice().(*AddonServiceChoice_NginxMgmtSuite); ok {
		return x.NginxMgmtSuite
	}
	return false
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*AddonServiceChoice) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*AddonServiceChoice_VesIoVolterraDefault)(nil),
		(*AddonServiceChoice_VesIoTenantManagement)(nil),
		(*AddonServiceChoice_VesIoScim)(nil),
		(*AddonServiceChoice_ShapeBot)(nil),
		(*AddonServiceChoice_ShapeRecognize)(nil),
		(*AddonServiceChoice_AidataBfdp)(nil),
		(*AddonServiceChoice_LilacCdn)(nil),
		(*AddonServiceChoice_NginxMgmtSuite)(nil),
	}
}

func init() {
	proto.RegisterType((*AddonServiceChoice)(nil), "ves.io.schema.vesenv.AddonServiceChoice")
}

func init() {
	proto.RegisterFile("ves.io/schema/vesenv/all_addon_services.proto", fileDescriptor_24b1043c1548ccb0)
}

var fileDescriptor_24b1043c1548ccb0 = []byte{
	// 921 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x94, 0x4d, 0x6f, 0xdc, 0x44,
	0x1c, 0xc6, 0x6d, 0x88, 0xa2, 0xc4, 0x41, 0xb4, 0x98, 0x02, 0x6e, 0x41, 0x96, 0x15, 0x56, 0xa8,
	0x97, 0xd9, 0xf5, 0xfb, 0xcb, 0xb1, 0x9b, 0x8a, 0x6e, 0x10, 0xcd, 0x61, 0x83, 0x78, 0x97, 0xac,
	0x79, 0xb3, 0x63, 0xe1, 0x9d, 0x59, 0xad, 0x27, 0x4b, 0x1b, 0x2e, 0xfd, 0x08, 0x88, 0xcf, 0xc0,
	0xa1, 0xdf, 0xc1, 0xb7, 0x3d, 0x71, 0x8c, 0xf6, 0xd4, 0x23, 0xd9, 0x5c, 0x10, 0xa7, 0x7e, 0x04,
	0x34, 0x63, 0x67, 0xd3, 0x4a, 0xdc, 0x92, 0x79, 0x9e, 0x79, 0xfe, 0xbf, 0x9d, 0xc7, 0xfa, 0x1b,
	0x60, 0x49, 0x9b, 0x61, 0xc5, 0x47, 0x0d, 0x3e, 0xa3, 0x33, 0x38, 0x5a, 0xd2, 0x86, 0xb2, 0xe5,
	0x08, 0xd6, 0x75, 0x0e, 0x09, 0xe1, 0x2c, 0x6f, 0xe8, 0x62, 0x59, 0x61, 0xda, 0x0c, 0xe7, 0x0b,
	0x2e, 0xb8, 0x79, 0xaf, 0xb3, 0x0f, 0x3b, 0xfb, 0xb0, 0xb3, 0x3f, 0x38, 0xfc, 0xdf, 0x10, 0x3e,
	0x17, 0x15, 0x67, 0xfd, 0xcd, 0xc3, 0x7f, 0xf7, 0x0c, 0xf3, 0x91, 0x8c, 0x3c, 0xed, 0x12, 0x8f,
	0xce, 0x78, 0x85, 0xa9, 0xf9, 0x52, 0x37, 0x3e, 0x59, 0xd2, 0x26, 0xaf, 0x78, 0xbe, 0xe4, 0xb5,
	0xa0, 0x8b, 0x05, 0xcc, 0x09, 0x2d, 0xe0, 0x79, 0x2d, 0x2c, 0xdd, 0xd1, 0x1f, 0xee, 0x8d, 0xf9,
	0xaa, 0xb5, 0x9e, 0x28, 0x13, 0xa8, 0x38, 0xb8, 0x31, 0x81, 0xde, 0x64, 0x0e, 0x12, 0x98, 0x40,
	0x82, 0xd2, 0x08, 0xc4, 0x31, 0xf2, 0x40, 0x48, 0xbc, 0x00, 0x20, 0x94, 0x40, 0xe0, 0x61, 0x9a,
	0xa4, 0x59, 0xe2, 0xa6, 0x71, 0xec, 0x3e, 0xd8, 0x6d, 0x9e, 0x37, 0x82, 0xce, 0xd6, 0xad, 0xe5,
	0x18, 0xef, 0x2e, 0x69, 0x63, 0xde, 0xff, 0xb6, 0x0f, 0x72, 0x1e, 0x77, 0x41, 0x4e, 0xcf, 0xd5,
	0x4c, 0xb4, 0xa9, 0xfc, 0x95, 0xc7, 0xfc, 0xc6, 0xd1, 0x1b, 0xcc, 0x3f, 0x75, 0xc3, 0xea, 0x51,
	0x05, 0x65, 0x90, 0x89, 0x7c, 0x06, 0x19, 0x2c, 0xe9, 0x8c, 0x32, 0x61, 0xbd, 0xa3, 0x58, 0xab,
	0x55, 0x6b, 0x4d, 0x94, 0x4b, 0xb2, 0x76, 0x2e, 0x70, 0xeb, 0x32, 0x07, 0x18, 0x87, 0xa9, 0x4b,
	0x33, 0x02, 0xb2, 0x20, 0xcd, 0x40, 0x18, 0xb9, 0x19, 0x48, 0xb3, 0x14, 0x03, 0xec, 0x87, 0x1e,
	0x25, 0x11, 0x2e, 0x90, 0x1f, 0xbf, 0x01, 0x7b, 0xdf, 0xd8, 0xa1, 0xcf, 0x7f, 0x85, 0xe6, 0x07,
	0xdf, 0xa8, 0x28, 0xe7, 0xe9, 0x36, 0x6a, 0xa2, 0x4d, 0x3f, 0x52, 0x94, 0x9d, 0x72, 0x2b, 0x98,
	0x3f, 0x18, 0x07, 0x3d, 0x65, 0x83, 0xab, 0x99, 0xb5, 0xa3, 0xc0, 0x92, 0x55, 0x6b, 0x05, 0x4a,
	0x90, 0x60, 0x52, 0x90, 0x0f, 0x47, 0x0b, 0x1a, 0x47, 0x31, 0x40, 0x2e, 0x49, 0x80, 0xe7, 0x51,
	0x0c, 0x50, 0xe6, 0x66, 0xc0, 0xf5, 0x43, 0x1f, 0x62, 0xcf, 0x77, 0x5d, 0xd7, 0x9f, 0x68, 0xd3,
	0x7d, 0x35, 0xe6, 0x54, 0x5e, 0xb9, 0x30, 0xf6, 0x9b, 0x33, 0x38, 0xa7, 0x39, 0xe2, 0xc2, 0xf2,
	0x55, 0xf0, 0x4f, 0xab, 0xd6, 0xf2, 0xfa, 0x63, 0x80, 0xb8, 0x30, 0x07, 0xae, 0x1f, 0x45, 0x28,
	0x24, 0x19, 0xc8, 0x52, 0x94, 0x81, 0xd0, 0xcf, 0x52, 0x90, 0x45, 0x61, 0x02, 0x82, 0x38, 0x76,
	0xfd, 0x08, 0xa5, 0x08, 0x41, 0xb4, 0x6e, 0xad, 0x43, 0xe3, 0x43, 0x5c, 0x57, 0x94, 0x09, 0xd0,
	0x54, 0x84, 0xca, 0x3a, 0x29, 0x6b, 0xa8, 0x79, 0x30, 0xe6, 0x42, 0x56, 0x22, 0xff, 0x99, 0x68,
	0xd3, 0x3d, 0x15, 0x3c, 0xe6, 0xc2, 0xfc, 0x43, 0x37, 0xee, 0x74, 0xc3, 0x17, 0x14, 0xf3, 0x92,
	0x55, 0x17, 0xd4, 0x0a, 0x14, 0x42, 0xb9, 0x6a, 0xad, 0xa4, 0x17, 0xc1, 0x56, 0x34, 0x07, 0x19,
	0xc6, 0x30, 0x2d, 0x62, 0x02, 0xe2, 0x22, 0x0a, 0x40, 0xe8, 0x85, 0x05, 0xc8, 0x62, 0x1f, 0x02,
	0x8a, 0xfc, 0x38, 0xc2, 0xae, 0xeb, 0x17, 0x7e, 0xbc, 0x6e, 0xad, 0x87, 0xc6, 0xfe, 0xed, 0xa5,
	0x4f, 0x1f, 0x9d, 0x8b, 0x33, 0xca, 0x44, 0x85, 0xa1, 0xfc, 0x78, 0x9d, 0x63, 0x26, 0x68, 0x5d,
	0x57, 0x25, 0x65, 0x58, 0xe2, 0xbc, 0xaf, 0x86, 0x4c, 0xb7, 0xf6, 0x0b, 0xe3, 0x00, 0x56, 0x04,
	0x0a, 0x98, 0xa3, 0x82, 0xcc, 0xad, 0x50, 0xf1, 0x7c, 0xd7, 0xbd, 0x75, 0x27, 0x00, 0x29, 0x98,
	0x03, 0x48, 0x32, 0x8c, 0xfd, 0x30, 0x00, 0x21, 0x8d, 0x10, 0x08, 0x3d, 0x18, 0x80, 0x34, 0xc8,
	0x7c, 0x10, 0x90, 0x14, 0xf9, 0x38, 0x41, 0x04, 0xe1, 0x70, 0xdd, 0x5a, 0x9f, 0x19, 0x3b, 0xca,
	0x7f, 0x6f, 0x5c, 0x95, 0xce, 0x97, 0x91, 0x23, 0x13, 0x9c, 0x79, 0x0d, 0x45, 0xc1, 0x17, 0xb3,
	0x89, 0x36, 0x35, 0xba, 0xd0, 0xb1, 0xf4, 0xfc, 0x66, 0xec, 0xd7, 0x55, 0x0d, 0x71, 0x8e, 0x09,
	0xb3, 0x22, 0x35, 0xf9, 0xe7, 0xae, 0x0c, 0x75, 0x0c, 0x30, 0x61, 0xe6, 0x20, 0x25, 0x49, 0x42,
	0xdc, 0x00, 0x03, 0x9c, 0x85, 0x45, 0xd7, 0x71, 0x46, 0xe2, 0xf0, 0xad, 0x8e, 0xd7, 0xad, 0xf5,
	0xb9, 0x71, 0x07, 0x13, 0x86, 0x39, 0x63, 0x14, 0x0b, 0xbe, 0x68, 0x96, 0xd8, 0xbc, 0x7b, 0xf4,
	0xf8, 0xc4, 0xf9, 0x9a, 0x43, 0x82, 0x60, 0x0d, 0x19, 0xa6, 0x0b, 0xd9, 0x86, 0x4a, 0x3e, 0x22,
	0x4c, 0xb6, 0x71, 0x97, 0x95, 0x15, 0x7b, 0x96, 0xcf, 0xca, 0x99, 0xc8, 0x9b, 0xf3, 0x4a, 0x50,
	0x2b, 0x56, 0x10, 0xc5, 0xaa, 0xb5, 0xd2, 0x5e, 0x05, 0x52, 0x05, 0x4a, 0x35, 0x07, 0xae, 0x17,
	0xba, 0x41, 0x0c, 0x33, 0x10, 0xd1, 0x20, 0x06, 0x61, 0x5a, 0x20, 0x80, 0x12, 0xe2, 0x81, 0x18,
	0xfa, 0xc8, 0x0f, 0xdc, 0x18, 0xa2, 0x28, 0x59, 0xb7, 0xd6, 0x17, 0xc6, 0x7b, 0x6c, 0xd6, 0x6c,
	0x59, 0xcc, 0x8f, 0x4f, 0x9e, 0x1c, 0x9f, 0x7c, 0xff, 0xc6, 0xa7, 0xef, 0x9c, 0xca, 0x3c, 0xd9,
	0x86, 0x9a, 0xf1, 0xb4, 0x9c, 0x09, 0x75, 0x32, 0xde, 0x33, 0x76, 0xb1, 0xda, 0x2a, 0xe3, 0x17,
	0xfa, 0xe5, 0x95, 0xad, 0xbd, 0xba, 0xb2, 0xb5, 0xd7, 0x57, 0xb6, 0xfe, 0x62, 0x63, 0xeb, 0x2f,
	0x37, 0xb6, 0xfe, 0xd7, 0xc6, 0xd6, 0x2f, 0x37, 0xb6, 0xfe, 0xf7, 0xc6, 0xd6, 0xff, 0xd9, 0xd8,
	0xda, 0xeb, 0x8d, 0xad, 0xff, 0x7e, 0x6d, 0x6b, 0x97, 0xd7, 0xb6, 0xf6, 0xea, 0xda, 0xd6, 0x7e,
	0xfc, 0xaa, 0xe4, 0xf3, 0x5f, 0xca, 0xe1, 0xcd, 0x8e, 0x19, 0x9e, 0x37, 0x23, 0xf5, 0x87, 0x7c,
	0x7d, 0x30, 0x5f, 0xf0, 0x65, 0x45, 0xe8, 0x62, 0xbb, 0x82, 0x46, 0x73, 0x54, 0xf2, 0x11, 0x7d,
	0x26, 0xfa, 0xb5, 0xf7, 0xd6, 0xf6, 0x43, 0xbb, 0x6a, 0xed, 0x05, 0xff, 0x05, 0x00, 0x00, 0xff,
	0xff, 0x71, 0xf9, 0x6e, 0x48, 0x61, 0x05, 0x00, 0x00,
}

func (this *AddonServiceChoice) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*AddonServiceChoice)
	if !ok {
		that2, ok := that.(AddonServiceChoice)
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
	if that1.Choice == nil {
		if this.Choice != nil {
			return false
		}
	} else if this.Choice == nil {
		return false
	} else if !this.Choice.Equal(that1.Choice) {
		return false
	}
	return true
}
func (this *AddonServiceChoice_VesIoVolterraDefault) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*AddonServiceChoice_VesIoVolterraDefault)
	if !ok {
		that2, ok := that.(AddonServiceChoice_VesIoVolterraDefault)
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
	if this.VesIoVolterraDefault != that1.VesIoVolterraDefault {
		return false
	}
	return true
}
func (this *AddonServiceChoice_VesIoTenantManagement) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*AddonServiceChoice_VesIoTenantManagement)
	if !ok {
		that2, ok := that.(AddonServiceChoice_VesIoTenantManagement)
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
	if this.VesIoTenantManagement != that1.VesIoTenantManagement {
		return false
	}
	return true
}
func (this *AddonServiceChoice_VesIoScim) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*AddonServiceChoice_VesIoScim)
	if !ok {
		that2, ok := that.(AddonServiceChoice_VesIoScim)
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
	if this.VesIoScim != that1.VesIoScim {
		return false
	}
	return true
}
func (this *AddonServiceChoice_ShapeBot) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*AddonServiceChoice_ShapeBot)
	if !ok {
		that2, ok := that.(AddonServiceChoice_ShapeBot)
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
	if this.ShapeBot != that1.ShapeBot {
		return false
	}
	return true
}
func (this *AddonServiceChoice_ShapeRecognize) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*AddonServiceChoice_ShapeRecognize)
	if !ok {
		that2, ok := that.(AddonServiceChoice_ShapeRecognize)
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
	if this.ShapeRecognize != that1.ShapeRecognize {
		return false
	}
	return true
}
func (this *AddonServiceChoice_AidataBfdp) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*AddonServiceChoice_AidataBfdp)
	if !ok {
		that2, ok := that.(AddonServiceChoice_AidataBfdp)
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
	if this.AidataBfdp != that1.AidataBfdp {
		return false
	}
	return true
}
func (this *AddonServiceChoice_LilacCdn) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*AddonServiceChoice_LilacCdn)
	if !ok {
		that2, ok := that.(AddonServiceChoice_LilacCdn)
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
	if this.LilacCdn != that1.LilacCdn {
		return false
	}
	return true
}
func (this *AddonServiceChoice_NginxMgmtSuite) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*AddonServiceChoice_NginxMgmtSuite)
	if !ok {
		that2, ok := that.(AddonServiceChoice_NginxMgmtSuite)
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
	if this.NginxMgmtSuite != that1.NginxMgmtSuite {
		return false
	}
	return true
}
func (this *AddonServiceChoice) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 12)
	s = append(s, "&vesenv.AddonServiceChoice{")
	if this.Choice != nil {
		s = append(s, "Choice: "+fmt.Sprintf("%#v", this.Choice)+",\n")
	}
	s = append(s, "}")
	return strings.Join(s, "")
}
func (this *AddonServiceChoice_VesIoVolterraDefault) GoString() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&vesenv.AddonServiceChoice_VesIoVolterraDefault{` +
		`VesIoVolterraDefault:` + fmt.Sprintf("%#v", this.VesIoVolterraDefault) + `}`}, ", ")
	return s
}
func (this *AddonServiceChoice_VesIoTenantManagement) GoString() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&vesenv.AddonServiceChoice_VesIoTenantManagement{` +
		`VesIoTenantManagement:` + fmt.Sprintf("%#v", this.VesIoTenantManagement) + `}`}, ", ")
	return s
}
func (this *AddonServiceChoice_VesIoScim) GoString() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&vesenv.AddonServiceChoice_VesIoScim{` +
		`VesIoScim:` + fmt.Sprintf("%#v", this.VesIoScim) + `}`}, ", ")
	return s
}
func (this *AddonServiceChoice_ShapeBot) GoString() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&vesenv.AddonServiceChoice_ShapeBot{` +
		`ShapeBot:` + fmt.Sprintf("%#v", this.ShapeBot) + `}`}, ", ")
	return s
}
func (this *AddonServiceChoice_ShapeRecognize) GoString() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&vesenv.AddonServiceChoice_ShapeRecognize{` +
		`ShapeRecognize:` + fmt.Sprintf("%#v", this.ShapeRecognize) + `}`}, ", ")
	return s
}
func (this *AddonServiceChoice_AidataBfdp) GoString() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&vesenv.AddonServiceChoice_AidataBfdp{` +
		`AidataBfdp:` + fmt.Sprintf("%#v", this.AidataBfdp) + `}`}, ", ")
	return s
}
func (this *AddonServiceChoice_LilacCdn) GoString() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&vesenv.AddonServiceChoice_LilacCdn{` +
		`LilacCdn:` + fmt.Sprintf("%#v", this.LilacCdn) + `}`}, ", ")
	return s
}
func (this *AddonServiceChoice_NginxMgmtSuite) GoString() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&vesenv.AddonServiceChoice_NginxMgmtSuite{` +
		`NginxMgmtSuite:` + fmt.Sprintf("%#v", this.NginxMgmtSuite) + `}`}, ", ")
	return s
}
func valueToGoStringAllAddonServices(v interface{}, typ string) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("func(v %v) *%v { return &v } ( %#v )", typ, typ, pv)
}
func (m *AddonServiceChoice) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *AddonServiceChoice) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AddonServiceChoice) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Choice != nil {
		{
			size := m.Choice.Size()
			i -= size
			if _, err := m.Choice.MarshalTo(dAtA[i:]); err != nil {
				return 0, err
			}
		}
	}
	return len(dAtA) - i, nil
}

func (m *AddonServiceChoice_VesIoVolterraDefault) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AddonServiceChoice_VesIoVolterraDefault) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	i--
	if m.VesIoVolterraDefault {
		dAtA[i] = 1
	} else {
		dAtA[i] = 0
	}
	i--
	dAtA[i] = 0x8
	return len(dAtA) - i, nil
}
func (m *AddonServiceChoice_VesIoTenantManagement) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AddonServiceChoice_VesIoTenantManagement) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	i--
	if m.VesIoTenantManagement {
		dAtA[i] = 1
	} else {
		dAtA[i] = 0
	}
	i--
	dAtA[i] = 0x10
	return len(dAtA) - i, nil
}
func (m *AddonServiceChoice_VesIoScim) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AddonServiceChoice_VesIoScim) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	i--
	if m.VesIoScim {
		dAtA[i] = 1
	} else {
		dAtA[i] = 0
	}
	i--
	dAtA[i] = 0x20
	return len(dAtA) - i, nil
}
func (m *AddonServiceChoice_ShapeBot) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AddonServiceChoice_ShapeBot) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	i--
	if m.ShapeBot {
		dAtA[i] = 1
	} else {
		dAtA[i] = 0
	}
	i--
	dAtA[i] = 0x3
	i--
	dAtA[i] = 0x90
	return len(dAtA) - i, nil
}
func (m *AddonServiceChoice_ShapeRecognize) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AddonServiceChoice_ShapeRecognize) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	i--
	if m.ShapeRecognize {
		dAtA[i] = 1
	} else {
		dAtA[i] = 0
	}
	i--
	dAtA[i] = 0x3
	i--
	dAtA[i] = 0x98
	return len(dAtA) - i, nil
}
func (m *AddonServiceChoice_AidataBfdp) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AddonServiceChoice_AidataBfdp) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	i--
	if m.AidataBfdp {
		dAtA[i] = 1
	} else {
		dAtA[i] = 0
	}
	i--
	dAtA[i] = 0x3
	i--
	dAtA[i] = 0xa0
	return len(dAtA) - i, nil
}
func (m *AddonServiceChoice_LilacCdn) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AddonServiceChoice_LilacCdn) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	i--
	if m.LilacCdn {
		dAtA[i] = 1
	} else {
		dAtA[i] = 0
	}
	i--
	dAtA[i] = 0x3
	i--
	dAtA[i] = 0xa8
	return len(dAtA) - i, nil
}
func (m *AddonServiceChoice_NginxMgmtSuite) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AddonServiceChoice_NginxMgmtSuite) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	i--
	if m.NginxMgmtSuite {
		dAtA[i] = 1
	} else {
		dAtA[i] = 0
	}
	i--
	dAtA[i] = 0x3
	i--
	dAtA[i] = 0xb0
	return len(dAtA) - i, nil
}
func encodeVarintAllAddonServices(dAtA []byte, offset int, v uint64) int {
	offset -= sovAllAddonServices(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *AddonServiceChoice) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Choice != nil {
		n += m.Choice.Size()
	}
	return n
}

func (m *AddonServiceChoice_VesIoVolterraDefault) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	n += 2
	return n
}
func (m *AddonServiceChoice_VesIoTenantManagement) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	n += 2
	return n
}
func (m *AddonServiceChoice_VesIoScim) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	n += 2
	return n
}
func (m *AddonServiceChoice_ShapeBot) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	n += 3
	return n
}
func (m *AddonServiceChoice_ShapeRecognize) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	n += 3
	return n
}
func (m *AddonServiceChoice_AidataBfdp) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	n += 3
	return n
}
func (m *AddonServiceChoice_LilacCdn) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	n += 3
	return n
}
func (m *AddonServiceChoice_NginxMgmtSuite) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	n += 3
	return n
}

func sovAllAddonServices(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozAllAddonServices(x uint64) (n int) {
	return sovAllAddonServices(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *AddonServiceChoice) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&AddonServiceChoice{`,
		`Choice:` + fmt.Sprintf("%v", this.Choice) + `,`,
		`}`,
	}, "")
	return s
}
func (this *AddonServiceChoice_VesIoVolterraDefault) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&AddonServiceChoice_VesIoVolterraDefault{`,
		`VesIoVolterraDefault:` + fmt.Sprintf("%v", this.VesIoVolterraDefault) + `,`,
		`}`,
	}, "")
	return s
}
func (this *AddonServiceChoice_VesIoTenantManagement) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&AddonServiceChoice_VesIoTenantManagement{`,
		`VesIoTenantManagement:` + fmt.Sprintf("%v", this.VesIoTenantManagement) + `,`,
		`}`,
	}, "")
	return s
}
func (this *AddonServiceChoice_VesIoScim) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&AddonServiceChoice_VesIoScim{`,
		`VesIoScim:` + fmt.Sprintf("%v", this.VesIoScim) + `,`,
		`}`,
	}, "")
	return s
}
func (this *AddonServiceChoice_ShapeBot) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&AddonServiceChoice_ShapeBot{`,
		`ShapeBot:` + fmt.Sprintf("%v", this.ShapeBot) + `,`,
		`}`,
	}, "")
	return s
}
func (this *AddonServiceChoice_ShapeRecognize) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&AddonServiceChoice_ShapeRecognize{`,
		`ShapeRecognize:` + fmt.Sprintf("%v", this.ShapeRecognize) + `,`,
		`}`,
	}, "")
	return s
}
func (this *AddonServiceChoice_AidataBfdp) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&AddonServiceChoice_AidataBfdp{`,
		`AidataBfdp:` + fmt.Sprintf("%v", this.AidataBfdp) + `,`,
		`}`,
	}, "")
	return s
}
func (this *AddonServiceChoice_LilacCdn) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&AddonServiceChoice_LilacCdn{`,
		`LilacCdn:` + fmt.Sprintf("%v", this.LilacCdn) + `,`,
		`}`,
	}, "")
	return s
}
func (this *AddonServiceChoice_NginxMgmtSuite) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&AddonServiceChoice_NginxMgmtSuite{`,
		`NginxMgmtSuite:` + fmt.Sprintf("%v", this.NginxMgmtSuite) + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringAllAddonServices(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *AddonServiceChoice) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowAllAddonServices
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
			return fmt.Errorf("proto: AddonServiceChoice: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: AddonServiceChoice: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field VesIoVolterraDefault", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAllAddonServices
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			b := bool(v != 0)
			m.Choice = &AddonServiceChoice_VesIoVolterraDefault{b}
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field VesIoTenantManagement", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAllAddonServices
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			b := bool(v != 0)
			m.Choice = &AddonServiceChoice_VesIoTenantManagement{b}
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field VesIoScim", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAllAddonServices
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			b := bool(v != 0)
			m.Choice = &AddonServiceChoice_VesIoScim{b}
		case 50:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field ShapeBot", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAllAddonServices
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			b := bool(v != 0)
			m.Choice = &AddonServiceChoice_ShapeBot{b}
		case 51:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field ShapeRecognize", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAllAddonServices
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			b := bool(v != 0)
			m.Choice = &AddonServiceChoice_ShapeRecognize{b}
		case 52:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field AidataBfdp", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAllAddonServices
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			b := bool(v != 0)
			m.Choice = &AddonServiceChoice_AidataBfdp{b}
		case 53:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field LilacCdn", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAllAddonServices
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			b := bool(v != 0)
			m.Choice = &AddonServiceChoice_LilacCdn{b}
		case 54:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field NginxMgmtSuite", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAllAddonServices
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			b := bool(v != 0)
			m.Choice = &AddonServiceChoice_NginxMgmtSuite{b}
		default:
			iNdEx = preIndex
			skippy, err := skipAllAddonServices(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthAllAddonServices
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthAllAddonServices
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
func skipAllAddonServices(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowAllAddonServices
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
					return 0, ErrIntOverflowAllAddonServices
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
					return 0, ErrIntOverflowAllAddonServices
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
				return 0, ErrInvalidLengthAllAddonServices
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupAllAddonServices
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthAllAddonServices
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthAllAddonServices        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowAllAddonServices          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupAllAddonServices = fmt.Errorf("proto: unexpected end of group")
)
