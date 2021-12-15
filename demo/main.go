package main

import (
	"os"
	"os/exec"
	"path/filepath"

	demo "github.com/saschagrunert/demo"
)

func main() {
	d := demo.New()
	d.Add(kwctlRun(), "kwctl demo", "kwctl")
	d.Add(policyServerRun(), "policy-server demo", "policy-server")
	d.Add(gatekeeperPolicyBuildAndRun(), "gatekeeper policy build and run demo", "gatekeeper")
	d.Run()
}

func kwctlRun() *demo.Run {
	r := demo.NewRun(
		"Running policies with kwctl",
	)

	r.Setup(cleanupKwctl)
	r.Cleanup(cleanupKwctl)

	kwctl(r)

	return r
}

func kwctl(r *demo.Run) {
	r.Step(demo.S(
		"List policies",
	), demo.S("kwctl policies"))

	r.Step(demo.S(
		"Pull a policy",
	), demo.S("kwctl pull registry://ghcr.io/kubewarden/policies/safe-annotations:v0.1.0"))

	r.Step(demo.S(
		"List policies",
	), demo.S("kwctl policies"))

	r.Step(demo.S(
		"Inspect policy",
	), demo.S("kwctl inspect registry://ghcr.io/kubewarden/policies/safe-annotations:v0.1.0"))

	r.Step(demo.S(
		"Request with a letsencrypt-production issuer",
	), demo.S("bat test_data/production-ingress.json"))

	r.Step(demo.S(
		"Evaluate request with a letsencrypt-production issuer",
	), demo.S("kwctl -v run",
		`--settings-json '{"constrained_annotations": {"cert-manager.io/cluster-issuer": "letsencrypt-production"}}'`,
		"--request-path test_data/production-ingress.json",
		"registry://registry.ereslibre.net/kubewarden/policies/safe-annotations:v0.1.0 | jq"))

	r.Step(demo.S(
		"Request with a letsencrypt-staging issuer",
	), demo.S("bat test_data/staging-ingress.json"))

	r.StepCanFail(demo.S(
		"Evaluate request with a letsencrypt-staging issuer",
	), demo.S("kwctl -v run",
		`--settings-json '{"constrained_annotations": {"cert-manager.io/cluster-issuer": "letsencrypt-production"}}'`,
		"--request-path test_data/staging-ingress.json",
		"registry://registry.ereslibre.net/kubewarden/policies/safe-annotations:v0.1.0 | jq"))
}

func policyServerRun() *demo.Run {
	r := demo.NewRun(
		"Running policies on the policy-server",
	)

	r.Setup(setupKubernetes)
	r.Cleanup(cleanupKubernetes)

	policyServer(r, NoSkipPull)

	return r
}

type SkipPullOption int

const (
	NoSkipPull = iota
	SkipPull
)

func policyServer(r *demo.Run, skipPull SkipPullOption) {
	if skipPull == NoSkipPull {
		r.Step(demo.S(
			"List policies",
		), demo.S("kwctl policies"))

		r.Step(demo.S(
			"Pull a policy",
		), demo.S("kwctl pull registry://registry.ereslibre.net/kubewarden/policies/safe-annotations:v0.1.0"))

		r.Step(demo.S(
			"List policies",
		), demo.S("kwctl policies"))
	}

	r.Step(demo.S(
		"Generate Kubernetes manifest",
	), demo.S("kwctl manifest",
		"--type ClusterAdmissionPolicy",
		`--settings-json '{"constrained_annotations": {"cert-manager.io/cluster-issuer": "letsencrypt-production"}}'`,
		"registry://registry.ereslibre.net/kubewarden/policies/safe-annotations:v0.1.0 | bat --language yaml",
	))

	r.Step(demo.S(
		"Apply Kubernetes manifest",
	), demo.S(
		"kwctl manifest",
		"--type ClusterAdmissionPolicy",
		`--settings-json '{"constrained_annotations": {"cert-manager.io/cluster-issuer": "letsencrypt-production"}}'`,
		"registry://registry.ereslibre.net/kubewarden/policies/safe-annotations:v0.1.0 |",
		"kubectl apply -f -"))

	r.Step(demo.S(
		"Wait for our policy to be active",
	), demo.S(
		"kubectl wait --for=condition=PolicyServerWebhookConfigurationReconciled clusteradmissionpolicy generated-policy",
	))

	r.Step(demo.S(
		"Ingress with a letsencrypt-production issuer",
	), demo.S("bat test_data/production-ingress-resource.yaml"))

	r.Step(demo.S(
		"Deploy an Ingress resource with a letsencrypt-production issuer",
	), demo.S("kubectl apply -f test_data/production-ingress-resource.yaml"))

	r.Step(demo.S(
		"Ingress with a letsencrypt-staging issuer",
	), demo.S("bat test_data/staging-ingress-resource.yaml"))

	r.StepCanFail(demo.S(
		"Deploy an Ingress resource with a letsencrypt-staging issuer",
	), demo.S("kubectl apply -f test_data/staging-ingress-resource.yaml"))
}

func gatekeeperPolicyBuildAndRun() *demo.Run {
	r := demo.NewRun(
		"Running a gatekeeper policy",
	)

	r.Setup(setupKubernetes)
	r.Cleanup(cleanupKubernetes)

	r.Step(demo.S(
		"Show policy",
	), demo.S("bat gatekeeper/requiredlabels.rego"))

	r.Step(demo.S(
		"Build policy",
	), demo.S(
		"opa build -t wasm -e k8srequiredlabels/violation -o gatekeeper/bundle.tar.gz gatekeeper/requiredlabels.rego",
	))

	r.Step(demo.S(
		"Extract policy",
	), demo.S(
		"tar -C gatekeeper -xf gatekeeper/bundle.tar.gz /policy.wasm",
	))

	r.Step(demo.S(
		"Show a request that is valid -- contains an 'owner-team' key",
	), demo.S(
		"bat test_data/having-label-deployment.json",
	))

	r.Step(demo.S(
		"Run policy with a request that is valid",
	), demo.S(
		"kwctl run -e gatekeeper",
		`--settings-json '{"labels":[{"key":"owner-team"}]}'`,
		"--request-path test_data/having-label-deployment.json",
		"gatekeeper/policy.wasm | jq",
	))

	r.Step(demo.S(
		"Show a request that is invalid -- does not contain an 'owner-team' key",
	), demo.S(
		"bat test_data/missing-label-deployment.json",
	))

	r.StepCanFail(demo.S(
		"Run policy with a request that is invalid",
	), demo.S(
		"kwctl run -e gatekeeper",
		`--settings-json '{"labels":[{"key":"owner-team"}]}'`,
		"--request-path test_data/missing-label-deployment.json",
		"gatekeeper/policy.wasm | jq",
	))

	r.Step(demo.S(
		"Run the policy on top of Kubernetes",
	), demo.S(
		"bat kubernetes/required-owner-team.yaml",
	))

	r.Step(demo.S(
		"Run the policy on top of Kubernetes",
	), demo.S(
		"kubectl apply -f kubernetes/required-owner-team.yaml",
	))

	r.Step(demo.S(
		"Run the policy on top of Kubernetes",
	), demo.S(
		"kubectl wait --for=condition=PolicyServerWebhookConfigurationReconciled clusteradmissionpolicy required-owner-team",
	))

	r.Step(demo.S(
		"Run the policy on top of Kubernetes",
	), demo.S(
		"kubectl get -o wide clusteradmissionpolicy",
	))

	r.Step(demo.S(
		"Show a Deployment with an owner-team label",
	), demo.S(
		"bat test_data/having-label-deployment-resource.yaml",
	))

	r.Step(demo.S(
		"Create a Deployment with an owner-team label",
	), demo.S(
		"kubectl apply -f test_data/having-label-deployment-resource.yaml",
	))

	r.Step(demo.S(
		"Show a Deployment without an owner-team label",
	), demo.S(
		"bat test_data/missing-label-deployment-resource.yaml",
	))

	r.StepCanFail(demo.S(
		"Try to create a Deployment with a missing owner-team label",
	), demo.S(
		"kubectl apply -f test_data/missing-label-deployment-resource.yaml",
	))

	return r
}

func cleanupKwctl() error {
	os.RemoveAll(filepath.Join(os.Getenv("HOME"), ".cache", "kubewarden"))
	return nil
}

func setupKubernetes() error {
	cleanupKwctl()
	cleanupKubernetes()
	exec.Command("kubectl", "create", "namespace", "rancher-online-meetup-21").Run()
	exec.Command("kubectl", "delete", "clusteradmissionpolicy", "--all").Run()
	return nil
}

func cleanupKubernetes() error {
	cleanupKwctl()
	exec.Command("kubectl", "delete", "namespace", "rancher-online-meetup-21").Run()
	exec.Command("kubectl", "delete", "clusteradmissionpolicy", "--all").Run()
	return nil
}
