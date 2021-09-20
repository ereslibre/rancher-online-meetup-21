package main

import (
	"os"
	"os/exec"
	"path/filepath"

	demo "github.com/saschagrunert/demo"
)

func main() {
	d := demo.New()
	d.Add(containerDays21Run(), "containerdays 21 demo", "containerdays 21 demo")
	d.Add(kwctlRun(), "kwctl demo", "kwctl demo")
	d.Add(policyServerRun(), "policy-server demo", "policy-server demo")
	d.Add(gatekeeperPolicyBuildAndRun(), "gatekeeper policy build and run demo", "gatekeeper policy build and run demo")
	d.Run()
}

func containerDays21Run() *demo.Run {
	r := demo.NewRun(
		"Running policies with kwctl and policy-server",
	)

	r.Setup(setupKubernetes)
	r.Cleanup(cleanupKubernetes)

	kwctl(r)
	policyServer(r, SkipPull)

	return r
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
		"registry://ghcr.io/kubewarden/policies/safe-annotations:v0.1.0 | jq"))

	r.Step(demo.S(
		"Request with a letsencrypt-staging issuer",
	), demo.S("bat test_data/staging-ingress.json"))

	r.StepCanFail(demo.S(
		"Evaluate request with a letsencrypt-staging issuer",
	), demo.S("kwctl -v run",
		`--settings-json '{"constrained_annotations": {"cert-manager.io/cluster-issuer": "letsencrypt-production"}}'`,
		"--request-path test_data/staging-ingress.json",
		"registry://ghcr.io/kubewarden/policies/safe-annotations:v0.1.0 | jq"))
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
		), demo.S("kwctl pull registry://ghcr.io/kubewarden/policies/safe-annotations:v0.1.0"))

		r.Step(demo.S(
			"List policies",
		), demo.S("kwctl policies"))
	}

	r.Step(demo.S(
		"Generate Kubernetes manifest",
	), demo.S("kwctl manifest",
		"--type ClusterAdmissionPolicy",
		`--settings-json '{"constrained_annotations": {"cert-manager.io/cluster-issuer": "letsencrypt-production"}}'`,
		"registry://ghcr.io/kubewarden/policies/safe-annotations:v0.1.0 | bat --language yaml",
	))

	r.Step(demo.S(
		"Apply Kubernetes manifest",
	), demo.S(
		"kwctl manifest",
		"--type ClusterAdmissionPolicy",
		`--settings-json '{"constrained_annotations": {"cert-manager.io/cluster-issuer": "letsencrypt-production"}}'`,
		"registry://ghcr.io/kubewarden/policies/safe-annotations:v0.1.0 |",
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
		"Show  a request that is valid -- contains an 'owner-team' key",
	), demo.S(
		"bat test_data/having-label-ingress.json",
	))

	r.Step(demo.S(
		"Run policy with a request that is valid",
	), demo.S(
		"kwctl run -e gatekeeper",
		`--settings-json '{"labels":[{"key":"owner-team"}]}'`,
		"--request-path test_data/having-label-ingress.json",
		"gatekeeper/policy.wasm | jq",
	))

	r.Step(demo.S(
		"Show a request that is invalid -- does not contain an 'owner-team' key",
	), demo.S(
		"bat test_data/missing-label-ingress.json",
	))

	r.StepCanFail(demo.S(
		"Run policy with a request that is invalid",
	), demo.S(
		"kwctl run -e gatekeeper",
		`--settings-json '{"labels":[{"key":"owner-team"}]}'`,
		"--request-path test_data/missing-label-ingress.json",
		"gatekeeper/policy.wasm | jq",
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
	exec.Command("kubectl", "create", "namespace", "containerdays-21").Run()
	exec.Command("kubectl", "delete", "clusteradmissionpolicy", "--all").Run()
	return nil
}

func cleanupKubernetes() error {
	cleanupKwctl()
	exec.Command("kubectl", "delete", "namespace", "containerdays-21").Run()
	exec.Command("kubectl", "delete", "clusteradmissionpolicy", "--all").Run()
	return nil
}
