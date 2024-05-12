/*
Copyright 2024 baranitharan.chittharanjan@spark.co.nz.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

const (
	EventSource                 = "spark-issuer"
	EventReasonIssuerReconciler = "ClusterIssuerReconciler"
)

// ClusterIssuerSpec defines the desired state of ClusterIssuer
type ClusterIssuerSpec struct {
	// URL is the REST API login URL for the external issuer to rerieve the session ID
	// example: https://appviewx.com/login
	URL string `json:"url"`

	// Reference to the secret that's holding the login credentials for the REST API
	AuthSecretName string `json:"authSecretName"`
}

// ClusterIssuerStatus defines the observed state of ClusterIssuer
type ClusterIssuerStatus struct {

	// list of status conditions to indicate the status of cluster issuer
	// known conditions are 'Ready'.
	// +optional
	Conditions []ClusterIssuerCondition `json:"conditions,omitempty"`

	// sessionID from the remote API
	// +optional
	SessionID string `json:"sessionID,omitempty"`

	// last successful timestamp of retrieved sessionID
	// +optional
	LastPollTime *metav1.Time `json:"lastPollTime,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster

// ClusterIssuer is the Schema for the clusterissuers API
// +kubebuilder:printcolumn:name="Type",type="string",JSONPath=".status.conditions[].type",description="whether clusterissuer is ready to serve"
// +kubebuilder:printcolumn:name="ReadyForServing",type="string",JSONPath=".status.conditions[].status",description="whether clusterissuer is ready to serve"
type ClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterIssuerSpec   `json:"spec,omitempty"`
	Status ClusterIssuerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ClusterIssuerList contains a list of ClusterIssuer
type ClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterIssuer `json:"items"`
}

type ClusterIssuerCondition struct {
	// Type of the condition, known values are 'Ready'.
	Type ClusterIssuerConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown')
	Status ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp of the last update to the status
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is the machine readable explanation for object's condition
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message is the human readable explanation for object's condition
	Message string `json:"message"`
}

// IssuerConditionType represents an Issuer condition value.
type ClusterIssuerConditionType string

const (
	// ClusterIssuerConditionReady represents the fact that a given ClusterIssuer condition
	// is in ready state and able to issue certificates.
	// If the `status` of this condition is `False`, CertificateRequest controllers
	// should prevent attempts to sign certificates.
	ClusterIssuerConditionReady ClusterIssuerConditionType = "Ready"
)

// ConditionStatus represents a condition's status.
// +kubebuilder:validation:Enum=True;False;Unknown
type ConditionStatus string

// These are valid condition statuses. "ConditionTrue" means a resource is in
// the condition; "ConditionFalse" means a resource is not in the condition;
// "ConditionUnknown" means kubernetes can't decide if a resource is in the
// condition or not. In the future, we could add other intermediate
// conditions, e.g. ConditionDegraded.
const (
	// ConditionTrue represents the fact that a given condition is true
	ConditionTrue ConditionStatus = "True"

	// ConditionFalse represents the fact that a given condition is false
	ConditionFalse ConditionStatus = "False"

	// ConditionUnknown represents the fact that a given condition is unknown
	ConditionUnknown ConditionStatus = "Unknown"
)

func init() {
	SchemeBuilder.Register(&ClusterIssuer{}, &ClusterIssuerList{})
}
