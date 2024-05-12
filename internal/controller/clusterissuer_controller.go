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

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	corev1 "k8s.io/api/core/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	sparkissuerv1alpha1 "spark.co.nz/sparkissuer/api/v1alpha1"

	sparkissuerutil "spark.co.nz/sparkissuer/internal/ClusterIssuer/util"
)

const (
	defaultHealthCheckInterval = time.Minute
)

var (
	errGetAuthSecret = errors.New("failed to get Secret containing Issuer credentials")
)

// ClusterIssuerReconciler reconciles a ClusterIssuer object
type ClusterIssuerReconciler struct {
	client.Client
	Scheme                   *runtime.Scheme
	Kind                     string
	ClusterResourceNamespace string
	recorder                 record.EventRecorder
}

//+kubebuilder:rbac:groups=spark-issuer.spark.co.nz,resources=clusterissuers,verbs=get;list;watch
//+kubebuilder:rbac:groups=spark-issuer.spark.co.nz,resources=clusterissuers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *ClusterIssuerReconciler) newIssuer() (client.Object, error) {
	clusterissuerGVK := sparkissuerv1alpha1.GroupVersion.WithKind(r.Kind)
	ro, err := r.Scheme.New(clusterissuerGVK)
	if err != nil {
		return nil, err
	}
	return ro.(client.Object), nil
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ClusterIssuer object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.17.2/pkg/reconcile
func (r *ClusterIssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	_ = log.FromContext(ctx)

	// TODO(user): your logic here

	issuer, err := r.newIssuer()
	if err != nil {
		log.Log.Error(err, "unrecognized issuer type")
		return ctrl.Result{}, nil
	}
	if err := r.Get(ctx, req.NamespacedName, issuer); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %v", err)
		}
		log.Log.Info("Clusterissuerr is tot found. Ignoring.")
		return ctrl.Result{}, nil
	}

	issuerSpec, issuerStatus, err := sparkissuerutil.GetSpecAndStatus(issuer)
	if err != nil {
		log.Log.Error(err, "Unexpected error while getting issuer spec and status. Not retrying.")
		return ctrl.Result{}, nil
	}

	// report gives feedback by updating the Ready conidtion of the cluster issuer
	report := func(conditionStatus sparkissuerv1alpha1.ConditionStatus, message string, err error) {
		eventType := corev1.EventTypeNormal
		if err != nil {
			log.Log.Error(err, message)
			eventType = corev1.EventTypeWarning
			message = fmt.Sprintf("%s: %v", message, err)
		} else {
			log.Log.Info(message)
		}
		r.recorder.Event(issuer, eventType, sparkissuerv1alpha1.EventReasonIssuerReconciler, message)
		sparkissuerutil.SetReadyCondition(issuerStatus, conditionStatus, sparkissuerv1alpha1.EventReasonIssuerReconciler, message)
	}

	defer func() {
		if err != nil {
			report(sparkissuerv1alpha1.ConditionFalse, "Temporary error. Retrying...", err)
		}
		if updateErr := r.Status().Update(ctx, issuer); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	if ready := sparkissuerutil.GetReadyCondition(issuerStatus); ready == nil {
		report(sparkissuerv1alpha1.ConditionUnknown, "First Seen", nil)
		return ctrl.Result{}, nil
	}

	secretName := types.NamespacedName{
		Name: issuerSpec.AuthSecretName,
	}

	switch issuer.(type) {
	case *sparkissuerv1alpha1.ClusterIssuer:
		secretName.Namespace = r.ClusterResourceNamespace
	default:
		log.Log.Error(fmt.Errorf("unexpected issuer type: %s", issuer), "not retrying")
		return ctrl.Result{}, err
	}

	var secret corev1.Secret

	if err := r.Get(ctx, secretName, &secret); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w, secret name: %s, reason: %v", errGetAuthSecret, secretName, err)
	}

	code := sparkissuerutil.CheckServerAliveness(issuerSpec.URL)
	if code != 200 {
		return ctrl.Result{}, fmt.Errorf("remote API server is returning status code %d, please check the connectivity", code)
	}
	username := secret.Data["username"]
	password := secret.Data["password"]
	pastTime := time.Now().Add(-14 * time.Minute)
	timeDiff := issuerStatus.LastPollTime.Time.Before(pastTime)
	if issuerStatus.SessionID == "" || issuerStatus.LastPollTime == nil || timeDiff {
		err = sparkissuerutil.SetSessionID(issuerStatus, username, password, issuerSpec.URL)
		if err != nil {
			return ctrl.Result{}, err
		}
	}
	report(sparkissuerv1alpha1.ConditionTrue, "success", nil)
	return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterIssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.recorder = mgr.GetEventRecorderFor(sparkissuerv1alpha1.EventSource)
	return ctrl.NewControllerManagedBy(mgr).
		For(&sparkissuerv1alpha1.ClusterIssuer{}).
		Complete(r)
}
