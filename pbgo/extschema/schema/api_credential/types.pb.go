// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: ves.io/schema/api_credential/types.proto

package api_credential

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/protobuf/gogoproto"
import google_protobuf1 "github.com/gogo/protobuf/types"
import _ "github.com/volterraedge/terraform-provider-volterra/pbgo/extschema/schema"
import ves_io_schema4 "github.com/volterraedge/terraform-provider-volterra/pbgo/extschema/schema"
import _ "github.com/volterraedge/terraform-provider-volterra/pbgo/extschema/schema"

import strconv "strconv"

import strings "strings"
import reflect "reflect"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// API Credential type
//
// x-displayName: "Credential Type"
// Types of API credential given when requesting credentials from volterra
type APICredentialType int32

const (
	// x-displayName: "User Certificate"
	// Volterra user certificate to access Volterra public API using mTLS
	// using self credential (my credential)
	API_CERTIFICATE APICredentialType = 0
	// x-displayName: "Kubernetes Config File"
	// Kubernetes config file to access Virtual Kubernetes API in Volterra
	// using self credential (my credential)
	KUBE_CONFIG APICredentialType = 1
	// x-displayName: "API Token"
	// API token to access Volterra public API
	// using self credential (my credential)
	API_TOKEN APICredentialType = 2
	// x-displayName: "Service API Token"
	// API token for service credentials
	// using service user credential (service credential)
	SERVICE_API_TOKEN APICredentialType = 3
	// x-displayName: "Service API Certificate"
	// API certificate for service credentials
	// using service user credential (service credential)
	SERVICE_API_CERTIFICATE APICredentialType = 4
	// x-displayName: " Kubernetes Config File for Service Credential"
	// Service Credential kubeconfig
	// using service user credential (service credential)
	SERVICE_KUBE_CONFIG APICredentialType = 5
	// x-displayName: "Site Global Kubeconfig"
	// Kubeconfig for accessing Site via Global Controller
	SITE_GLOBAL_KUBE_CONFIG APICredentialType = 6
)

var APICredentialType_name = map[int32]string{
	0: "API_CERTIFICATE",
	1: "KUBE_CONFIG",
	2: "API_TOKEN",
	3: "SERVICE_API_TOKEN",
	4: "SERVICE_API_CERTIFICATE",
	5: "SERVICE_KUBE_CONFIG",
	6: "SITE_GLOBAL_KUBE_CONFIG",
}
var APICredentialType_value = map[string]int32{
	"API_CERTIFICATE":         0,
	"KUBE_CONFIG":             1,
	"API_TOKEN":               2,
	"SERVICE_API_TOKEN":       3,
	"SERVICE_API_CERTIFICATE": 4,
	"SERVICE_KUBE_CONFIG":     5,
	"SITE_GLOBAL_KUBE_CONFIG": 6,
}

func (APICredentialType) EnumDescriptor() ([]byte, []int) { return fileDescriptorTypes, []int{0} }

// API credentials
//
// x-displayName: "API Credentials"
// Keeps track of user requested API credentials
type GlobalSpecType struct {
	// API Credential type
	//
	// x-displayName: "Credential Type"
	// Type of API credential
	Type APICredentialType `protobuf:"varint,1,opt,name=type,proto3,enum=ves.io.schema.api_credential.APICredentialType" json:"type,omitempty"`
	// user requesting credential
	//
	// x-displayName: "User"
	// Reference to user for whom API credential is created
	Users []*ves_io_schema4.ObjectRefType `protobuf:"bytes,2,rep,name=users" json:"users,omitempty"`
	// Virtual K8s namespace
	//
	// x-displayName: "Namespace"
	// Namespace of virtual_k8s
	VirtualK8SNamespace string `protobuf:"bytes,3,opt,name=virtual_k8s_namespace,json=virtualK8sNamespace,proto3" json:"virtual_k8s_namespace,omitempty"`
	// Virtual K8s
	//
	// x-displayName: "Virtual K8s"
	// Name of virtual K8s cluster
	VirtualK8SName string `protobuf:"bytes,4,opt,name=virtual_k8s_name,json=virtualK8sName,proto3" json:"virtual_k8s_name,omitempty"`
	// Digest sha1
	//
	// x-displayName: "Digest sha1"
	// Digest sha1 of credential
	Digest string `protobuf:"bytes,5,opt,name=digest,proto3" json:"digest,omitempty"`
	// Created timestamp
	//
	// x-displayName: "Created timestamp"
	// Timestamp of credential creation
	CreatedTimestamp *google_protobuf1.Timestamp `protobuf:"bytes,6,opt,name=created_timestamp,json=createdTimestamp" json:"created_timestamp,omitempty"`
	// Expiry timestamp
	//
	// x-displayName: "Expiry timestamp"
	// Timestamp of credential expiration
	ExpirationTimestamp *google_protobuf1.Timestamp `protobuf:"bytes,7,opt,name=expiration_timestamp,json=expirationTimestamp" json:"expiration_timestamp,omitempty"`
	// Active
	//
	// x-displayName: "Active"
	// Possibility to deactivate/activate credential with no deletion
	Active bool `protobuf:"varint,8,opt,name=active,proto3" json:"active,omitempty"`
	// Certificate Serial Number
	//
	// x-displayName: "Certificate Serial Number"
	// Serial number of the client certificate part of credential type API Certificate or Kubeconfig
	CertificateSerialNum string `protobuf:"bytes,9,opt,name=certificate_serial_num,json=certificateSerialNum,proto3" json:"certificate_serial_num,omitempty"`
	// Site Name
	//
	// x-displayName: "Site Name"
	// Site name when global kubeconfig is issued for physical k8s site
	SiteName string `protobuf:"bytes,10,opt,name=site_name,json=siteName,proto3" json:"site_name,omitempty"`
}

func (m *GlobalSpecType) Reset()                    { *m = GlobalSpecType{} }
func (*GlobalSpecType) ProtoMessage()               {}
func (*GlobalSpecType) Descriptor() ([]byte, []int) { return fileDescriptorTypes, []int{0} }

func (m *GlobalSpecType) GetType() APICredentialType {
	if m != nil {
		return m.Type
	}
	return API_CERTIFICATE
}

func (m *GlobalSpecType) GetUsers() []*ves_io_schema4.ObjectRefType {
	if m != nil {
		return m.Users
	}
	return nil
}

func (m *GlobalSpecType) GetVirtualK8SNamespace() string {
	if m != nil {
		return m.VirtualK8SNamespace
	}
	return ""
}

func (m *GlobalSpecType) GetVirtualK8SName() string {
	if m != nil {
		return m.VirtualK8SName
	}
	return ""
}

func (m *GlobalSpecType) GetDigest() string {
	if m != nil {
		return m.Digest
	}
	return ""
}

func (m *GlobalSpecType) GetCreatedTimestamp() *google_protobuf1.Timestamp {
	if m != nil {
		return m.CreatedTimestamp
	}
	return nil
}

func (m *GlobalSpecType) GetExpirationTimestamp() *google_protobuf1.Timestamp {
	if m != nil {
		return m.ExpirationTimestamp
	}
	return nil
}

func (m *GlobalSpecType) GetActive() bool {
	if m != nil {
		return m.Active
	}
	return false
}

func (m *GlobalSpecType) GetCertificateSerialNum() string {
	if m != nil {
		return m.CertificateSerialNum
	}
	return ""
}

func (m *GlobalSpecType) GetSiteName() string {
	if m != nil {
		return m.SiteName
	}
	return ""
}

func init() {
	proto.RegisterType((*GlobalSpecType)(nil), "ves.io.schema.api_credential.GlobalSpecType")
	proto.RegisterEnum("ves.io.schema.api_credential.APICredentialType", APICredentialType_name, APICredentialType_value)
}
func (x APICredentialType) String() string {
	s, ok := APICredentialType_name[int32(x)]
	if ok {
		return s
	}
	return strconv.Itoa(int(x))
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
	if this.Type != that1.Type {
		return false
	}
	if len(this.Users) != len(that1.Users) {
		return false
	}
	for i := range this.Users {
		if !this.Users[i].Equal(that1.Users[i]) {
			return false
		}
	}
	if this.VirtualK8SNamespace != that1.VirtualK8SNamespace {
		return false
	}
	if this.VirtualK8SName != that1.VirtualK8SName {
		return false
	}
	if this.Digest != that1.Digest {
		return false
	}
	if !this.CreatedTimestamp.Equal(that1.CreatedTimestamp) {
		return false
	}
	if !this.ExpirationTimestamp.Equal(that1.ExpirationTimestamp) {
		return false
	}
	if this.Active != that1.Active {
		return false
	}
	if this.CertificateSerialNum != that1.CertificateSerialNum {
		return false
	}
	if this.SiteName != that1.SiteName {
		return false
	}
	return true
}
func (this *GlobalSpecType) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 14)
	s = append(s, "&api_credential.GlobalSpecType{")
	s = append(s, "Type: "+fmt.Sprintf("%#v", this.Type)+",\n")
	if this.Users != nil {
		s = append(s, "Users: "+fmt.Sprintf("%#v", this.Users)+",\n")
	}
	s = append(s, "VirtualK8SNamespace: "+fmt.Sprintf("%#v", this.VirtualK8SNamespace)+",\n")
	s = append(s, "VirtualK8SName: "+fmt.Sprintf("%#v", this.VirtualK8SName)+",\n")
	s = append(s, "Digest: "+fmt.Sprintf("%#v", this.Digest)+",\n")
	if this.CreatedTimestamp != nil {
		s = append(s, "CreatedTimestamp: "+fmt.Sprintf("%#v", this.CreatedTimestamp)+",\n")
	}
	if this.ExpirationTimestamp != nil {
		s = append(s, "ExpirationTimestamp: "+fmt.Sprintf("%#v", this.ExpirationTimestamp)+",\n")
	}
	s = append(s, "Active: "+fmt.Sprintf("%#v", this.Active)+",\n")
	s = append(s, "CertificateSerialNum: "+fmt.Sprintf("%#v", this.CertificateSerialNum)+",\n")
	s = append(s, "SiteName: "+fmt.Sprintf("%#v", this.SiteName)+",\n")
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
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *GlobalSpecType) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Type != 0 {
		dAtA[i] = 0x8
		i++
		i = encodeVarintTypes(dAtA, i, uint64(m.Type))
	}
	if len(m.Users) > 0 {
		for _, msg := range m.Users {
			dAtA[i] = 0x12
			i++
			i = encodeVarintTypes(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if len(m.VirtualK8SNamespace) > 0 {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintTypes(dAtA, i, uint64(len(m.VirtualK8SNamespace)))
		i += copy(dAtA[i:], m.VirtualK8SNamespace)
	}
	if len(m.VirtualK8SName) > 0 {
		dAtA[i] = 0x22
		i++
		i = encodeVarintTypes(dAtA, i, uint64(len(m.VirtualK8SName)))
		i += copy(dAtA[i:], m.VirtualK8SName)
	}
	if len(m.Digest) > 0 {
		dAtA[i] = 0x2a
		i++
		i = encodeVarintTypes(dAtA, i, uint64(len(m.Digest)))
		i += copy(dAtA[i:], m.Digest)
	}
	if m.CreatedTimestamp != nil {
		dAtA[i] = 0x32
		i++
		i = encodeVarintTypes(dAtA, i, uint64(m.CreatedTimestamp.Size()))
		n1, err := m.CreatedTimestamp.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	if m.ExpirationTimestamp != nil {
		dAtA[i] = 0x3a
		i++
		i = encodeVarintTypes(dAtA, i, uint64(m.ExpirationTimestamp.Size()))
		n2, err := m.ExpirationTimestamp.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n2
	}
	if m.Active {
		dAtA[i] = 0x40
		i++
		if m.Active {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i++
	}
	if len(m.CertificateSerialNum) > 0 {
		dAtA[i] = 0x4a
		i++
		i = encodeVarintTypes(dAtA, i, uint64(len(m.CertificateSerialNum)))
		i += copy(dAtA[i:], m.CertificateSerialNum)
	}
	if len(m.SiteName) > 0 {
		dAtA[i] = 0x52
		i++
		i = encodeVarintTypes(dAtA, i, uint64(len(m.SiteName)))
		i += copy(dAtA[i:], m.SiteName)
	}
	return i, nil
}

func encodeVarintTypes(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *GlobalSpecType) Size() (n int) {
	var l int
	_ = l
	if m.Type != 0 {
		n += 1 + sovTypes(uint64(m.Type))
	}
	if len(m.Users) > 0 {
		for _, e := range m.Users {
			l = e.Size()
			n += 1 + l + sovTypes(uint64(l))
		}
	}
	l = len(m.VirtualK8SNamespace)
	if l > 0 {
		n += 1 + l + sovTypes(uint64(l))
	}
	l = len(m.VirtualK8SName)
	if l > 0 {
		n += 1 + l + sovTypes(uint64(l))
	}
	l = len(m.Digest)
	if l > 0 {
		n += 1 + l + sovTypes(uint64(l))
	}
	if m.CreatedTimestamp != nil {
		l = m.CreatedTimestamp.Size()
		n += 1 + l + sovTypes(uint64(l))
	}
	if m.ExpirationTimestamp != nil {
		l = m.ExpirationTimestamp.Size()
		n += 1 + l + sovTypes(uint64(l))
	}
	if m.Active {
		n += 2
	}
	l = len(m.CertificateSerialNum)
	if l > 0 {
		n += 1 + l + sovTypes(uint64(l))
	}
	l = len(m.SiteName)
	if l > 0 {
		n += 1 + l + sovTypes(uint64(l))
	}
	return n
}

func sovTypes(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozTypes(x uint64) (n int) {
	return sovTypes(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *GlobalSpecType) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&GlobalSpecType{`,
		`Type:` + fmt.Sprintf("%v", this.Type) + `,`,
		`Users:` + strings.Replace(fmt.Sprintf("%v", this.Users), "ObjectRefType", "ves_io_schema4.ObjectRefType", 1) + `,`,
		`VirtualK8SNamespace:` + fmt.Sprintf("%v", this.VirtualK8SNamespace) + `,`,
		`VirtualK8SName:` + fmt.Sprintf("%v", this.VirtualK8SName) + `,`,
		`Digest:` + fmt.Sprintf("%v", this.Digest) + `,`,
		`CreatedTimestamp:` + strings.Replace(fmt.Sprintf("%v", this.CreatedTimestamp), "Timestamp", "google_protobuf1.Timestamp", 1) + `,`,
		`ExpirationTimestamp:` + strings.Replace(fmt.Sprintf("%v", this.ExpirationTimestamp), "Timestamp", "google_protobuf1.Timestamp", 1) + `,`,
		`Active:` + fmt.Sprintf("%v", this.Active) + `,`,
		`CertificateSerialNum:` + fmt.Sprintf("%v", this.CertificateSerialNum) + `,`,
		`SiteName:` + fmt.Sprintf("%v", this.SiteName) + `,`,
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
			wire |= (uint64(b) & 0x7F) << shift
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
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Type", wireType)
			}
			m.Type = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Type |= (APICredentialType(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Users", wireType)
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
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Users = append(m.Users, &ves_io_schema4.ObjectRefType{})
			if err := m.Users[len(m.Users)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field VirtualK8SNamespace", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.VirtualK8SNamespace = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field VirtualK8SName", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.VirtualK8SName = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Digest", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Digest = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CreatedTimestamp", wireType)
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
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.CreatedTimestamp == nil {
				m.CreatedTimestamp = &google_protobuf1.Timestamp{}
			}
			if err := m.CreatedTimestamp.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 7:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ExpirationTimestamp", wireType)
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
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.ExpirationTimestamp == nil {
				m.ExpirationTimestamp = &google_protobuf1.Timestamp{}
			}
			if err := m.ExpirationTimestamp.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 8:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Active", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.Active = bool(v != 0)
		case 9:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CertificateSerialNum", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.CertificateSerialNum = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 10:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SiteName", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.SiteName = string(dAtA[iNdEx:postIndex])
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
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
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
			iNdEx += length
			if length < 0 {
				return 0, ErrInvalidLengthTypes
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowTypes
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipTypes(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}

var (
	ErrInvalidLengthTypes = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowTypes   = fmt.Errorf("proto: integer overflow")
)

func init() { proto.RegisterFile("ves.io/schema/api_credential/types.proto", fileDescriptorTypes) }

var fileDescriptorTypes = []byte{
	// 650 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x94, 0x3d, 0x6f, 0xd3, 0x40,
	0x18, 0xc7, 0x73, 0x79, 0xa3, 0xb9, 0x8a, 0x36, 0xb9, 0xf4, 0xc5, 0xa4, 0x95, 0x89, 0x98, 0x22,
	0xa4, 0xda, 0x52, 0x58, 0xba, 0xa1, 0x24, 0x72, 0x23, 0xab, 0x25, 0xa9, 0xdc, 0xc0, 0xc0, 0x62,
	0x5d, 0x9c, 0x8b, 0x7b, 0xd4, 0xce, 0x59, 0xe7, 0x73, 0xd4, 0x0e, 0x48, 0x0c, 0x7c, 0x00, 0xc4,
	0x27, 0x60, 0x44, 0x8c, 0x8c, 0x4c, 0x8c, 0x8c, 0x1d, 0x3b, 0x52, 0xb3, 0xc0, 0xd6, 0x8f, 0x80,
	0xfc, 0x92, 0x26, 0x29, 0x08, 0xb6, 0x7b, 0x9e, 0xff, 0xef, 0xff, 0xd7, 0xdd, 0xf3, 0xc8, 0x86,
	0x8d, 0x29, 0xf1, 0x15, 0xca, 0x54, 0xdf, 0x3a, 0x25, 0x2e, 0x56, 0xb1, 0x47, 0x4d, 0x8b, 0x93,
	0x11, 0x99, 0x08, 0x8a, 0x1d, 0x55, 0x5c, 0x78, 0xc4, 0x57, 0x3c, 0xce, 0x04, 0x43, 0xbb, 0x09,
	0xa9, 0x24, 0xa4, 0xb2, 0x4c, 0xd6, 0xf6, 0x6c, 0x2a, 0x4e, 0x83, 0xa1, 0x62, 0x31, 0x57, 0xb5,
	0x99, 0xcd, 0xd4, 0xd8, 0x34, 0x0c, 0xc6, 0x71, 0x15, 0x17, 0xf1, 0x29, 0x09, 0xab, 0x3d, 0xb4,
	0x19, 0xb3, 0x1d, 0x32, 0xa7, 0x04, 0x75, 0x89, 0x2f, 0xb0, 0xeb, 0xa5, 0xc0, 0xce, 0xf2, 0xbd,
	0x98, 0x27, 0x28, 0x9b, 0xa4, 0x57, 0xa9, 0x3d, 0x58, 0x16, 0x17, 0x6e, 0x59, 0xdb, 0x5d, 0x96,
	0xa6, 0xd8, 0xa1, 0x23, 0x2c, 0x48, 0xa2, 0x3e, 0xfa, 0x90, 0x87, 0x6b, 0x5d, 0x87, 0x0d, 0xb1,
	0x73, 0xe2, 0x11, 0x6b, 0x70, 0xe1, 0x11, 0xd4, 0x81, 0xf9, 0xc8, 0x2f, 0x81, 0x3a, 0x68, 0xac,
	0x35, 0x55, 0xe5, 0x5f, 0xaf, 0x54, 0x5a, 0xc7, 0x7a, 0xe7, 0xb6, 0x8a, 0xec, 0x46, 0x6c, 0x46,
	0x1a, 0x2c, 0x04, 0x3e, 0xe1, 0xbe, 0x94, 0xad, 0xe7, 0x1a, 0xab, 0xcd, 0xdd, 0x3b, 0x29, 0xfd,
	0xe1, 0x2b, 0x62, 0x09, 0x83, 0x8c, 0x23, 0x4b, 0xbb, 0xf2, 0xe9, 0x75, 0x3e, 0xa2, 0xbf, 0xfc,
	0xfa, 0x9a, 0x2b, 0xbc, 0x07, 0xd9, 0x32, 0x30, 0x12, 0x37, 0x6a, 0xc2, 0xcd, 0x29, 0xe5, 0x22,
	0xc0, 0x8e, 0x79, 0xb6, 0xef, 0x9b, 0x13, 0xec, 0x12, 0xdf, 0xc3, 0x16, 0x91, 0x72, 0x75, 0xd0,
	0x28, 0x19, 0xd5, 0x54, 0x3c, 0xdc, 0xf7, 0x7b, 0x33, 0x09, 0x35, 0x60, 0xf9, 0xae, 0x47, 0xca,
	0xc7, 0xf8, 0xda, 0x32, 0x8e, 0xb6, 0x60, 0x71, 0x44, 0x6d, 0xe2, 0x0b, 0xa9, 0x10, 0xeb, 0x69,
	0x85, 0xba, 0xb0, 0x62, 0x71, 0x82, 0x05, 0x19, 0x99, 0xb7, 0x5b, 0x90, 0x8a, 0x75, 0xd0, 0x58,
	0x6d, 0xd6, 0x94, 0x64, 0x4f, 0xca, 0x6c, 0x4f, 0xca, 0x60, 0x46, 0x18, 0xe5, 0xd4, 0x74, 0xdb,
	0x41, 0xcf, 0xe0, 0x06, 0x39, 0xf7, 0x28, 0xc7, 0xd1, 0xae, 0x16, 0xb2, 0xee, 0xfd, 0x37, 0xab,
	0x3a, 0xf7, 0xcd, 0xe3, 0xb6, 0x60, 0x11, 0x5b, 0x82, 0x4e, 0x89, 0xb4, 0x52, 0x07, 0x8d, 0x15,
	0x23, 0xad, 0xd0, 0x53, 0xb8, 0x65, 0x11, 0x2e, 0xe8, 0x98, 0x5a, 0x58, 0x10, 0xd3, 0x27, 0x9c,
	0x62, 0xc7, 0x9c, 0x04, 0xae, 0x54, 0x8a, 0xde, 0xd5, 0x2e, 0x45, 0x83, 0xcd, 0xf3, 0xac, 0x54,
	0x37, 0x36, 0x16, 0xc0, 0x93, 0x98, 0xeb, 0x05, 0x2e, 0xda, 0x81, 0x25, 0x9f, 0x0a, 0x92, 0xcc,
	0x0a, 0xc6, 0xb3, 0x58, 0x89, 0x1a, 0xd1, 0x94, 0x1e, 0x7f, 0x06, 0xb0, 0xf2, 0xc7, 0x9a, 0x51,
	0x15, 0xae, 0xb7, 0x8e, 0x75, 0xb3, 0xa3, 0x19, 0x03, 0xfd, 0x40, 0xef, 0xb4, 0x06, 0x5a, 0x39,
	0x83, 0xd6, 0xe1, 0xea, 0xe1, 0xf3, 0xb6, 0x66, 0x76, 0xfa, 0xbd, 0x03, 0xbd, 0x5b, 0x06, 0xe8,
	0x3e, 0x2c, 0x45, 0xd4, 0xa0, 0x7f, 0xa8, 0xf5, 0xca, 0x59, 0xb4, 0x09, 0x2b, 0x27, 0x9a, 0xf1,
	0x42, 0xef, 0x68, 0xe6, 0xbc, 0x9d, 0x43, 0x3b, 0x70, 0x7b, 0xb1, 0xbd, 0x98, 0x99, 0x47, 0xdb,
	0xb0, 0x3a, 0x13, 0x17, 0xb3, 0x0b, 0xb1, 0x4b, 0x1f, 0x68, 0x66, 0xf7, 0xa8, 0xdf, 0x6e, 0x1d,
	0x2d, 0x89, 0xc5, 0xf6, 0x5b, 0x70, 0x79, 0x2d, 0x67, 0xae, 0xae, 0xe5, 0xcc, 0xcd, 0xb5, 0x0c,
	0xde, 0x84, 0x32, 0xf8, 0x18, 0xca, 0xe0, 0x5b, 0x28, 0x83, 0xcb, 0x50, 0x06, 0x57, 0xa1, 0x0c,
	0xbe, 0x87, 0x32, 0xf8, 0x19, 0xca, 0x99, 0x9b, 0x50, 0x06, 0xef, 0x7e, 0xc8, 0x99, 0x97, 0x86,
	0xcd, 0xbc, 0x33, 0x5b, 0x99, 0x32, 0x47, 0x10, 0xce, 0xb1, 0x12, 0xf8, 0x6a, 0x7c, 0x18, 0x33,
	0xee, 0xee, 0x79, 0x9c, 0x4d, 0xe9, 0x88, 0xf0, 0xbd, 0x99, 0xac, 0x7a, 0x43, 0x9b, 0xa9, 0xe4,
	0x5c, 0xa4, 0xdf, 0xd5, 0x5f, 0x7f, 0x17, 0xc3, 0x62, 0xbc, 0xda, 0x27, 0xbf, 0x03, 0x00, 0x00,
	0xff, 0xff, 0x27, 0x9b, 0x7c, 0xda, 0x55, 0x04, 0x00, 0x00,
}
