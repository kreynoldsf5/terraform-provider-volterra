//
// Copyright (c) 2020 Volterra, Inc. Licensed under APACHE LICENSE, VERSION 2.0
//

package volterra

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	ves_schema "github.com/volterraedge/terraform-provider-volterra/pbgo/extschema/schema"
	ves_io_schema_api_credential "github.com/volterraedge/terraform-provider-volterra/pbgo/extschema/schema/api_credential"
	"gopkg.volterra.us/stdlib/codec"
	"gopkg.volterra.us/stdlib/svcfw"
)

const (
	svcCredRPCFQN    = "ves.io.schema.api_credential.CustomAPI"
	svcCredURI       = "/web/namespaces/system/service_credentials"
	deleteSvcCredURI = "/web/namespaces/system/revoke/service_credentials"
)

type svcCredentialParams struct {
	name        string
	svcCredType string
	nsRoles     []*ves_schema.NamespaceRoleType
	vk8sNS      string
	vk8sName    string
	password    string
	expirydays  uint32
}

// resourceVolterraSvcCredential is implementation of Volterra's API Credential Resource
func resourceVolterraSvcCredential() *schema.Resource {
	return &schema.Resource{
		Create: resourceVolterraSvcCredentialCreate,
		Read:   resourceVolterraSvcCredentialRead,
		Update: resourceVolterraSvcCredentialUpdate,
		Delete: resourceVolterraSvcCredentialDelete,

		Schema: map[string]*schema.Schema{

			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"svc_credential_type": {
				Type:     schema.TypeString,
				Required: true,
			},
			"namespace_roles": {
				Type:     schema.TypeString,
				Required: true,
			},
			"virtual_k8s_namespace": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"virtual_k8s_name": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"svc_credential_password": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"data": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"expiry_days": {
				Type:     schema.TypeInt,
				Default:  10,
				Optional: true,
			},
		},
	}
}

// resourceVolterraSvcCredentialCreate creates svc credential resource
func resourceVolterraSvcCredentialCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*APIClient)

	svcCredParams := &svcCredentialParams{}
	if v, ok := d.GetOk("name"); ok {
		svcCredParams.name = v.(string)
	}
	if v, ok := d.GetOk("svc_credential_type"); ok {
		svcCredParams.svcCredType = v.(string)
	}
	if v, ok := d.GetOk("virtual_k8s_namespace"); ok {
		svcCredParams.vk8sNS = v.(string)
	}
	if v, ok := d.GetOk("virtual_k8s_name"); ok {
		svcCredParams.vk8sName = v.(string)
	}
	if v, ok := d.GetOk("svc_credential_password"); ok {
		svcCredParams.password = v.(string)
	}
	if v, ok := d.GetOk("expiry_days"); ok {
		svcCredParams.expirydays = uint32(v.(int))
	}

	svcCredValue, ok := ves_io_schema_api_credential.APICredentialType_value[svcCredParams.svcCredType]
	if !ok {
		return fmt.Errorf("Invalid svc_credential_type, valid ones are: API_CERTIFICATE, KUBE_CONFIG, API_TOKEN")
	}

	svcCredReq := &ves_io_schema_api_credential.CreateServiceCredentialsRequest{
		Type:           svcCredParams.svcCredType,
		Name:           svcCredParams.name,
		Namespace:      svcfw.SystemNSVal,
		ExpirationDays: svcCredParams.expirydays,
		NamespaceRoles: svcCredParams.nsRoles,
	}

	svcCredSpec := &ves_io_schema_api_credential.CustomCreateSpecType{
		Type: ves_io_schema_api_credential.APICredentialType(svcCredValue),
	}

	if svcCredParams.vk8sName != "" {
		svcCredSpec.VirtualK8SName = svcCredParams.vk8sName
	}
	if svcCredParams.vk8sNS != "" {
		svcCredSpec.VirtualK8SNamespace = svcCredParams.vk8sNS
	}
	if svcCredParams.password != "" {
		svcCredSpec.Password = svcCredParams.password
	}
	svcCredReq.Spec = svcCredSpec

	yamlReq, err := codec.ToYAML(apiCredReq)
	if err != nil {
		return fmt.Errorf("Error marshalling rpc response to yaml: %s", err)
	}
	rspProto, err := client.CustomAPI(context.Background(), http.MethodPost, apiCredURI, fmt.Sprintf("%s.%s", apiCredRPCFQN, "Create"), yamlReq)
	if err != nil {
		return fmt.Errorf("Error creating API Credential: %s", err)
	}

	rspAPICred := rspProto.(*ves_io_schema_api_credential.CreateResponse)
	d.SetId(rspAPICred.Name)
	d.Set("data", rspAPICred.Data)
	return resourceVolterraSvcCredentialRead(d, meta)
}

func resourceVolterraSvcCredentialRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*APIClient)
	apiCredReq := &ves_io_schema_api_credential.GetRequest{
		Name:      d.Id(),
		Namespace: svcfw.SystemNSVal,
	}

	yamlReq, err := codec.ToYAML(apiCredReq)
	if err != nil {
		return fmt.Errorf("Error marshalling rpc response to yaml: %s", err)
	}
	_, err = client.CustomAPI(context.Background(), http.MethodGet, apiCredURI, fmt.Sprintf("%s.%s", apiCredRPCFQN, "Get"), yamlReq)
	if err != nil {
		if strings.Contains(err.Error(), "status code 404") {
			log.Printf("[INFO] API Credential %s no longer exists", d.Id())
			d.SetId("")
			return nil
		}
		return fmt.Errorf("Error finding Volterra API Credential resource %q: %s", d.Id(), err)
	}
	return nil
}

func resourceVolterraSvcCredentialUpdate(d *schema.ResourceData, meta interface{}) error {
	// cannot update api credential object
	return resourceVolterraSvcCredentialRead(d, meta)
}

func resourceVolterraSvcCredentialDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*APIClient)
	apiCredReq := &ves_io_schema_api_credential.GetRequest{
		Name:      d.Id(),
		Namespace: svcfw.SystemNSVal,
	}

	log.Printf("[DEBUG] Deleting/Revoking Volterra API credential obj %+v ", d.Id())
	yamlReq, err := codec.ToYAML(apiCredReq)
	if err != nil {
		return fmt.Errorf("Error marshalling rpc response to yaml: %s", err)
	}
	_, err = client.CustomAPI(context.Background(), http.MethodPost, deleteSvcCredURI, fmt.Sprintf("%s.%s", apiCredRPCFQN, "Revoke"), yamlReq)
	if err != nil {
		if strings.Contains(err.Error(), "status code 404") {
			log.Printf("[INFO] API Credential %s no longer exists", d.Id())
			d.SetId("")
			return nil
		}
	}
	return err
}
