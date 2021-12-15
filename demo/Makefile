.PHONY: install
install:
	helm install --namespace jaeger --create-namespace jaeger-operator jaegertracing/jaeger-operator
#	helm install --namespace jaeger --create-namespace jaeger jaegertracing/jaeger
	kubectl apply -f ../jaeger.yaml
	kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.5.3/cert-manager.yaml
	kubectl wait --for=condition=Available deployment --timeout=2m -n cert-manager --all
	helm install --wait --create-namespace --namespace prometheus --values ../kube-prometheus-values.yaml prometheus prometheus-community/kube-prometheus-stack
	kubectl apply -f https://github.com/open-telemetry/opentelemetry-operator/releases/latest/download/opentelemetry-operator.yaml
	kubectl wait --for=condition=Available deployment --timeout=2m -n opentelemetry-operator-system --all
	helm install --wait -n kubewarden --create-namespace kubewarden-crds kubewarden/charts/kubewarden/kubewarden-crds
	helm install --wait -n kubewarden kubewarden-controller --values ../values.yaml kubewarden/charts/kubewarden/kubewarden-controller
	kubectl port-forward --address 0.0.0.0 -n prometheus svc/prometheus-grafana 8080:80 &
	kubectl port-forward --address 0.0.0.0 -n jaeger svc/all-in-one-query 16686:16686 &

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
