package main_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	kubeassert "github.com/DWSR/kubeassert-go"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/restmapper"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
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
		kubeassert.NamespaceExists(nsName),
		kubeassert.NamespaceIsRestricted(nsName),
		kubeassert.CRDExists("sealedsecrets.bitnami.com", "v1alpha1"),
		kubeassert.DeploymentExists(nsName, deployName),
		kubeassert.PodDisruptionBudgetExists(nsName, deployName),
		kubeassert.PodDisruptionBudgetTargetsDeployment(nsName, deployName, deployName),
		kubeassert.DeploymentIsSystemClusterCritical(nsName, deployName),
		kubeassert.DeploymentHasCPURequests(nsName, deployName),
		kubeassert.DeploymentHasNoCPULimits(nsName, deployName),
		kubeassert.DeploymentHasMemoryRequests(nsName, deployName),
		kubeassert.DeploymentHasMemoryLimitsEqualToRequests(nsName, deployName),
		kubeassert.DeploymentAvailable(nsName, deployName),
		kubeassert.SecretExists(nsName, "test-sealing-key"),
		kubeassert.NamespaceExists(testNsName),
		kubeassert.SecretExists(testNsName, testSecretName),
		kubeassert.SecretHasContent(testNsName, testSecretName, map[string]string{
			//nolint:lll
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
		diskFS := filesys.MakeFsOnDisk()
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

		resMap, err := kust.Run(diskFS, kustPath)
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

		for _, res := range resMap.Resources() {
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

			yamlBytes, err := res.AsYAML()
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
