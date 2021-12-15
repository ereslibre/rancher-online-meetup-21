.PHONY: install
install:
	kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.5.3/cert-manager.yaml
	kubectl wait --for=condition=Available deployment --timeout=2m -n cert-manager --all
	helm install --wait --create-namespace --namespace prometheus --values ../kube-prometheus-values.yaml prometheus prometheus-community/kube-prometheus-stack
	kubectl apply -f https://github.com/open-telemetry/opentelemetry-operator/releases/latest/download/opentelemetry-operator.yaml
	kubectl wait --for=condition=Available deployment --timeout=2m -n opentelemetry-operator-system --all
	helm install --wait -n kubewarden --create-namespace kubewarden-crds kubewarden/kubewarden-crds
	helm install --wait -n kubewarden kubewarden-controller --values ../values.yaml kubewarden/kubewarden-controller
	helm install --namespace jaeger --create-namespace jaeger-operator jaegertracing/jaeger-operator

.PHONY: kwctl
kwctl:
	@clear
	@go run . --kwctl

.PHONY: policy-server
policy-server:
	@clear
	@go run . --policy-server

.PHONY: psp
psp-disallow-host-network:
	@clear
	@go run . --psp-disallow-host-network

.PHONY: gatekeeper
gatekeeper:
	@clear
	@go run . --gatekeeper
