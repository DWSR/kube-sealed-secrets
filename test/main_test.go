package main_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/restmapper"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/pkg/features"
	e2etypes "sigs.k8s.io/e2e-framework/pkg/types"
	"sigs.k8s.io/e2e-framework/third_party/kind"
	"sigs.k8s.io/kustomize/api/krusty"
	kusttypes "sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

var testEnv env.Environment

func TestMain(m *testing.M) {
	kindClusterName := envconf.RandomName("kind", 16)

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	testEnv = env.New().
		Setup(
			envfuncs.CreateCluster(kind.NewProvider(), kindClusterName),
			ApplyKustomization(".."),
			func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
				time.Sleep(1 * time.Second)
				return ctx, nil
			},
		).
		Finish(
			envfuncs.DestroyCluster(kindClusterName),
		)

	os.Exit(testEnv.Run(m))
}

func TestSealedSecrets(t *testing.T) {
	nsName := "sealed-secrets-system"
	deployName := "sealed-secrets-controller"

	testNsName := "sealed-secrets-test"
	testSecretName := "test-secret"

	tests := []e2etypes.Feature{
		NamespaceExists(nsName),
		NamespaceIsRestricted(nsName),
		CRDExists("sealedsecrets.bitnami.com", "v1alpha1"),
		DeploymentExists(nsName, deployName),
		PodDisruptionBudgetExists(nsName, deployName),
		PodDisruptionBudgetTargetsDeployment(nsName, deployName, deployName),
		DeploymentIsSystemClusterCritical(nsName, deployName),
		DeploymentHasCPURequests(nsName, deployName),
		DeploymentHasNoCPULimits(nsName, deployName),
		DeploymentHasMemoryRequests(nsName, deployName),
		DeploymentHasMemoryLimitsEqualToRequests(nsName, deployName),
		DeploymentAvailable(nsName, deployName),
		SecretExists(nsName, "test-sealing-key"),
		NamespaceExists(testNsName),
		SecretExists(testNsName, testSecretName),
		SecretHasContent(testNsName, testSecretName, map[string]string{
			"ipsumText": "Now that there is the Tec-9, a crappy spray gun from South Miami. This gun is advertised as the most popular gun in American crime. Do you believe that shit? It actually says that in the little book that comes with it: the most popular gun in American crime.\n",
		}),
	}

	testEnv.Test(t, tests...)
}

func ApplyKustomization(kustDir string) env.Func {
	var kustPath string

	testOverlayPath := filepath.Join(kustDir, "overlays", "test")
	liveOverlayPath := filepath.Join(kustDir, "overlays", "live")
	basePath := filepath.Join(kustDir, "base")

	if d, err := os.Stat(testOverlayPath); err == nil && d.IsDir() {
		kustPath = testOverlayPath
	} else if d, err := os.Stat(liveOverlayPath); err == nil && d.IsDir() {
		kustPath = liveOverlayPath
	} else if d, err := os.Stat(basePath); err == nil && d.IsDir() {
		kustPath = basePath
	}

	slog.Debug("calculated kustomization path", "path", kustPath)

	if kustPath == "" {
		slog.Error("no kustomization found")
		panic("No kustomization found")
	}

	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		fs := filesys.MakeFsOnDisk()
		opts := krusty.MakeDefaultOptions()
		opts.PluginConfig.HelmConfig = kusttypes.HelmConfig{
			Enabled: true,
			Command: "helm",
			Debug:   false,
		}
		opts.PluginConfig.FnpLoadingOptions.Network = true
		opts.LoadRestrictions = kusttypes.LoadRestrictionsNone
		opts.Reorder = krusty.ReorderOptionLegacy
		kust := krusty.MakeKustomizer(opts)

		slog.Debug("rendering kustomization")

		resMap, err := kust.Run(fs, kustPath)
		if err != nil {
			return ctx, err
		}

		slog.Debug("creating client")

		klient, err := cfg.NewClient()
		if err != nil {
			return ctx, err
		}

		client, err := dynamic.NewForConfig(klient.RESTConfig())
		if err != nil {
			return ctx, err
		}

		slog.Debug("applying kustomization")

		for _, r := range resMap.Resources() {
			// Do this inside the loop to account for new CRDs, etc. that get applied
			slog.Debug("creating resource mapper")
			discoveryClient, err := discovery.NewDiscoveryClientForConfig(klient.RESTConfig())
			if err != nil {
				return ctx, err
			}

			gr, err := restmapper.GetAPIGroupResources(discoveryClient)
			if err != nil {
				return ctx, err
			}

			restMapper := restmapper.NewDiscoveryRESTMapper(gr)
			slog.Debug("transmuting resMap resource to unstructured")
			yamlBytes, err := r.AsYAML()
			if err != nil {
				return ctx, err
			}

			obj := &unstructured.Unstructured{}
			decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(yamlBytes), len(yamlBytes))
			if err := decoder.Decode(obj); err != nil {
				return ctx, err
			}

			gvk := obj.GroupVersionKind()
			mapping, err := restMapper.RESTMapping(gvk.GroupKind(), gvk.Version)
			if err != nil {
				return ctx, err
			}

			slog.Debug("applying resource", "kind", obj.GetKind(), "name", obj.GetName(), "gvr", mapping.Resource)

			var resourceClient dynamic.ResourceInterface

			switch mapping.Scope.Name() {
			case meta.RESTScopeNameNamespace:
				resourceClient = client.Resource(mapping.Resource).Namespace(obj.GetNamespace())
			case meta.RESTScopeNameRoot:
				resourceClient = client.Resource(mapping.Resource)
			}

			_, err = resourceClient.Apply(ctx, obj.GetName(), obj, metav1.ApplyOptions{
				Force:        true,
				FieldManager: "e2e-test",
			})
			if err != nil {
				return ctx, err
			}
		}

		return ctx, nil
	}
}

func NamespaceIsRestricted(namespaceName string) e2etypes.Feature {
	return features.New("NamespaceIsRestricted").
		WithLabel("type", "namespace").
		AssessWithDescription("restrictedNamespace", "Namespace should be restricted", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			var ns corev1.Namespace
			err := cfg.Client().Resources().Get(ctx, namespaceName, "", &ns)
			require.NoError(t, err)

			nsLabels := ns.GetLabels()

			assert.Contains(t, nsLabels, "pod-security.kubernetes.io/enforce")
			assert.Equal(t, "restricted", nsLabels["pod-security.kubernetes.io/enforce"])
			assert.Contains(t, nsLabels, "pod-security.kubernetes.io/audit")
			assert.Equal(t, "restricted", nsLabels["pod-security.kubernetes.io/audit"])

			return ctx
		}).
		Feature()
}

func NamespaceExists(namespaceName string) e2etypes.Feature {
	return features.New("NamespaceExists").
		WithLabel("type", "namespace").
		AssessWithDescription("namespaceExists", "Namespace should exist", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			ns := &corev1.NamespaceList{
				Items: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}},
			}

			err := wait.For(conditions.New(cfg.Client().Resources()).ResourcesFound(ns), wait.WithTimeout(3*time.Second), wait.WithImmediate())
			require.NoError(t, err)

			return ctx
		}).
		Feature()
}

func DeploymentExists(namespaceName string, deploymentName string) e2etypes.Feature {
	return features.New("DeploymentExists").
		WithLabel("type", "deployment").
		AssessWithDescription("deploymentExists", "Deployment should exist", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			var dep appsv1.Deployment

			err := cfg.Client().Resources("deployments").WithNamespace(namespaceName).Get(ctx, deploymentName, namespaceName, &dep)
			require.NoError(t, err)

			return ctx
		}).
		Feature()
}

func DeploymentAvailable(namespaceName string, deploymentName string) e2etypes.Feature {
	return features.New("DeploymentAvailable").
		WithLabel("type", "deployment").
		AssessWithDescription("deploymentAvailable", "Deployment should be available", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			err := wait.For(
				conditions.New(cfg.Client().Resources()).DeploymentAvailable(deploymentName, namespaceName),
				wait.WithTimeout(2*time.Minute),
				wait.WithImmediate(),
			)
			require.NoError(t, err)

			return ctx
		}).
		Feature()
}

func SecretExists(namespaceName string, secretName string) e2etypes.Feature {
	return features.New("SecretExists").
		WithLabel("type", "secret").
		AssessWithDescription("secretExists", "Secret should exist", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			var sec corev1.Secret

			err := cfg.Client().Resources("secrets").WithNamespace(namespaceName).Get(ctx, secretName, namespaceName, &sec)
			require.NoError(t, err)

			return ctx
		}).
		Feature()
}

func SecretHasContent(namespaceName string, secretName string, content map[string]string) e2etypes.Feature {
	return features.New("SecretHasContent").
		WithLabel("type", "secret").
		AssessWithDescription("secretHasContent", "Secret should have content", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			var sec corev1.Secret

			err := cfg.Client().Resources("secrets").WithNamespace(namespaceName).Get(ctx, secretName, namespaceName, &sec)
			require.NoError(t, err)

			for k, v := range content {
				secData, exists := sec.Data[k]

				require.True(t, exists)
				assert.Equal(t, v, string(secData))
			}

			return ctx
		}).
		Feature()
}

func DeploymentIsSystemClusterCritical(namespaceName string, deploymentName string) e2etypes.Feature {
	return features.New("DeploymentIsSystemClusterCritical").
		WithLabel("type", "deployment").
		AssessWithDescription("deploymentIsSystemClusterCritical", "Deployment should be system-cluster-critical priority", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			var deploy appsv1.Deployment

			err := cfg.Client().Resources("deployments").WithNamespace(namespaceName).Get(ctx, deploymentName, namespaceName, &deploy)
			require.NoError(t, err)

			assert.Equal(t, "system-cluster-critical", deploy.Spec.Template.Spec.PriorityClassName)

			return ctx
		}).
		Feature()
}

func DeploymentHasNoCPULimits(namespaceName string, deploymentName string) e2etypes.Feature {
	return features.New("DeploymentHasNoCPULimits").
		WithLabel("type", "deployment").
		AssessWithDescription("deploymentHasNoCPULimits", "Deployment should have no CPU limits", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			var deploy appsv1.Deployment

			err := cfg.Client().Resources("deployments").WithNamespace(namespaceName).Get(ctx, deploymentName, namespaceName, &deploy)
			require.NoError(t, err)

			for _, container := range deploy.Spec.Template.Spec.Containers {
				assert.True(t, container.Resources.Limits.Cpu().IsZero())
			}

			return ctx
		}).
		Feature()
}

func DeploymentHasMemoryLimitsEqualToRequests(namespaceName string, deploymentName string) e2etypes.Feature {
	return features.New("DeploymentHasMemoryLimitsEqualToRequests").
		WithLabel("type", "deployment").
		AssessWithDescription("deploymentHasMemoryLimitsEqualToRequests", "Deployment should have memory limits equal to requests", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			var deploy appsv1.Deployment

			err := cfg.Client().Resources("deployments").WithNamespace(namespaceName).Get(ctx, deploymentName, namespaceName, &deploy)
			require.NoError(t, err)

			for _, container := range deploy.Spec.Template.Spec.Containers {
				assert.NotNil(t, container.Resources.Limits.Memory())
				assert.Equal(t, container.Resources.Requests.Memory(), container.Resources.Limits.Memory())
			}

			return ctx
		}).
		Feature()
}

func DeploymentHasMemoryRequests(namespaceName string, deploymentName string) e2etypes.Feature {
	return features.New("DeploymentHasMemoryRequests").
		WithLabel("type", "deployment").
		AssessWithDescription("deploymentHasMemoryRequests", "Deployment should have memory requests", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			var deploy appsv1.Deployment

			err := cfg.Client().Resources("deployments").WithNamespace(namespaceName).Get(ctx, deploymentName, namespaceName, &deploy)
			require.NoError(t, err)

			for _, container := range deploy.Spec.Template.Spec.Containers {
				assert.False(t, container.Resources.Requests.Memory().IsZero())
			}

			return ctx
		}).
		Feature()
}

func DeploymentHasCPURequests(namespaceName string, deploymentName string) e2etypes.Feature {
	return features.New("DeploymentHasCPURequests").
		WithLabel("type", "deployment").
		AssessWithDescription("deploymentHasCPURequests", "Deployment should have CPU requests", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			var deploy appsv1.Deployment

			err := cfg.Client().Resources("deployments").WithNamespace(namespaceName).Get(ctx, deploymentName, namespaceName, &deploy)
			require.NoError(t, err)

			for _, container := range deploy.Spec.Template.Spec.Containers {
				assert.False(t, container.Resources.Requests.Cpu().IsZero())
			}

			return ctx
		}).
		Feature()
}

func CRDExists(crdName string, crdVersion string) e2etypes.Feature {
	return features.New("CRDExists").
		WithLabel("type", "crd").
		AssessWithDescription("crdExists", "CRD should exist", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			var crd extv1.CustomResourceDefinition

			klient, err := cfg.NewClient()
			require.NoError(t, err)

			client, err := dynamic.NewForConfig(klient.RESTConfig())
			require.NoError(t, err)

			unstructuredCRD, err := client.
				Resource(extv1.SchemeGroupVersion.WithResource("customresourcedefinitions")).
				Get(ctx, crdName, metav1.GetOptions{})
			require.NoError(t, err)

			err = runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredCRD.UnstructuredContent(), &crd)
			require.NoError(t, err)

			foundVersion := false
			for _, v := range crd.Spec.Versions {
				if crdVersion == v.Name {
					foundVersion = true
				}
			}

			assert.True(t, foundVersion)

			return ctx
		}).
		Feature()
}

func PodDisruptionBudgetExists(namespaceName string, pdbName string) e2etypes.Feature {
	return features.New("PodDisruptionBudgetExists").
		WithLabel("type", "pdb").
		AssessWithDescription("pdbExists", "PDB should exist", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			var pdb policyv1.PodDisruptionBudget

			err := cfg.Client().Resources("poddisruptionbudgets").WithNamespace(namespaceName).Get(ctx, pdbName, namespaceName, &pdb)
			require.NoError(t, err)

			return ctx
		}).
		Feature()
}

func PodDisruptionBudgetTargetsDeployment(namespaceName string, pdbName string, deployName string) e2etypes.Feature {
	return features.New("PodDisruptionBudgetTargetsDeployment").
		WithLabel("type", "pdb").
		AssessWithDescription("pdbTargetsDeployment", "PDB should target deployment", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			var pdb policyv1.PodDisruptionBudget
			var deploy appsv1.Deployment

			err := cfg.Client().Resources("poddisruptionbudgets").WithNamespace(namespaceName).Get(ctx, pdbName, namespaceName, &pdb)
			require.NoError(t, err)

			err = cfg.Client().Resources("deployments").WithNamespace(namespaceName).Get(ctx, deployName, namespaceName, &deploy)
			require.NoError(t, err)

			for labelKey, labelValue := range pdb.Spec.Selector.MatchLabels {
				require.Equal(t, deploy.Spec.Selector.MatchLabels, labelKey)
				require.Equal(t, deploy.Spec.Selector.MatchLabels[labelKey], labelValue)
			}

			return ctx
		}).
		Feature()
}
