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

package util

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sparkissuerv1alpha1 "spark.co.nz/sparkissuer/api/v1alpha1"
)

// func basicAuth(username, password string) string {
// 	auth := username + ":" + password
// 	return base64.StdEncoding.EncodeToString([]byte(auth))
// }

type ServerResponse struct {
	Response struct {
		Status            string `json:"status"`
		AppStatusCode     any    `json:"appStatusCode"`
		StatusDescription any    `json:"statusDescription"`
		SessionID         string `json:"sessionId"`
		AuthCode          any    `json:"authCode"`
		LockDownPeriod    int    `json:"lockDownPeriod"`
		EmailID           any    `json:"emailId"`
		TermsAccepted     bool   `json:"termsAccepted"`
		PasswordExpiryMsg string `json:"passwordExpiryMsg"`
	} `json:"response"`
	Message       string `json:"message"`
	AppStatusCode any    `json:"appStatusCode"`
	Tags          any    `json:"tags"`
	Headers       any    `json:"headers"`
}

func GetSpecAndStatus(clusterissuer client.Object) (*sparkissuerv1alpha1.ClusterIssuerSpec, *sparkissuerv1alpha1.ClusterIssuerStatus, error) {
	switch t := clusterissuer.(type) {
	case *sparkissuerv1alpha1.ClusterIssuer:
		return &t.Spec, &t.Status, nil
	default:
		return nil, nil, fmt.Errorf("not an cluster issuer type: %t", t)
	}
}

func GetReadyCondition(status *sparkissuerv1alpha1.ClusterIssuerStatus) *sparkissuerv1alpha1.ClusterIssuerCondition {
	for _, c := range status.Conditions {
		if c.Type == sparkissuerv1alpha1.ClusterIssuerConditionReady {
			return &c
		}
	}
	return nil
}

func IsReady(status *sparkissuerv1alpha1.ClusterIssuerStatus) bool {
	if c := GetReadyCondition(status); c != nil {
		return c.Status == sparkissuerv1alpha1.ConditionTrue
	}
	return false
}

func SetReadyCondition(status *sparkissuerv1alpha1.ClusterIssuerStatus, conditionStatus sparkissuerv1alpha1.ConditionStatus, reason, message string) {
	ready := GetReadyCondition(status)
	if ready == nil {
		ready = &sparkissuerv1alpha1.ClusterIssuerCondition{
			Type: sparkissuerv1alpha1.ClusterIssuerConditionReady,
		}
		status.Conditions = append(status.Conditions, *ready)
	}
	if ready.Status != conditionStatus {
		ready.Status = conditionStatus
		now := metav1.Now()
		ready.LastTransitionTime = &now
	}
	ready.Reason = reason
	ready.Message = message

	for i, c := range status.Conditions {
		if c.Type == sparkissuerv1alpha1.ClusterIssuerConditionReady {
			status.Conditions[i] = *ready
			return
		}
	}
}

func SetSessionID(status *sparkissuerv1alpha1.ClusterIssuerStatus, username []byte, password []byte, url string) error {
	user := string(username)
	pass := string(password)
	sessionID, err := GetServerResponse(user, pass, url)
	if err != nil {
		return err
	}
	if sessionID != "" {
		status.SessionID = sessionID
		now := metav1.Now()
		status.LastPollTime = &now
	}
	return nil
}

func CheckServerAliveness(url string) int {
	resp, err := http.Get(url)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func GetServerResponse(username string, password string, url string) (string, error) {
	var data = strings.NewReader(`{}`)
	tr := http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &tr,
	}

	req, err := http.NewRequest("POST", url, data)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("username", username)
	req.Header.Set("password", password)
	// req.Header.Set("grant_type", "client_credentials")
	fmt.Println(req)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("error code %d is returned", resp.StatusCode)
	}
	ndata, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var response ServerResponse
	err = json.Unmarshal(ndata, &response)
	if err != nil {
		return "", err
	}
	return response.Response.SessionID, nil
}
