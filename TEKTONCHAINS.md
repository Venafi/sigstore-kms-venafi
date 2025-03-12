# Integration with Tekton Chains

## Requirements
* Follow the [Development](https://github.com/tektoncd/chains/blob/main/DEVELOPMENT.md) documentation for Tekton Chains


## Install Tekton Chains Controller with Venafi KMS Plugin

1. Create a Kubernetes secret in the tekton-chains namespace to represent the Venafi CodeSign Protect Oauth token that the `sigstore-kms-venafi` KMS plugin will use to authenticate

```bash
kubectl create secret generic venaficsp --from-literal=token='XXXXXXXXX' -n tekton-chains
```

2. From the locally forked chains folder update the `100-deployment.yaml` file as follows:

You will need to point to your [Venafi CodeSign Protect](https://venafi.com/codesign-protect/) instance by configuring `VSIGN_URL`.

You will also need to `signers.kms.kmsref` ConfigMap data entry to reference your specific code signing environment.

```yaml
# Copyright 2021 The Tekton Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

kind: Namespace
apiVersion: v1
metadata:
  name: tekton-chains
  labels:
    app.kubernetes.io/instance: default
    app.kubernetes.io/part-of: tekton-chains
---
apiVersion: v1
kind: Secret
metadata:
  name: signing-secrets
  namespace: tekton-chains
  labels:
    app.kubernetes.io/instance: default
    app.kubernetes.io/part-of: tekton-chains
# The data is populated at install time.
# data:
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: chains-config
  namespace: tekton-chains
  labels:
    app.kubernetes.io/instance: default
    app.kubernetes.io/part-of: tekton-chains
# The data can be tweaked at install time, it is commented out
# because these are the default settings.
data:
  artifacts.taskrun.format: in-toto
  artifacts.taskrun.storage: tekton
  artifacts.taskrun.signer: kms
  signers.kms.kmsref: venafi://container-signing-project\my-cert
#   artifacts.taskrun.signer: x509
#   artifacts.oci.storage: oci
#   artifacts.oci.format: simplesigning
#   artifacts.oci.signer: x509
#   transparency.enabled: false
#   transparency.url: https://rekor.sigstore.dev
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tekton-chains-controller
  namespace: tekton-chains
  labels:
    app.kubernetes.io/name: controller
    app.kubernetes.io/component: controller
    app.kubernetes.io/instance: default
    app.kubernetes.io/part-of: tekton-chains
    pipeline.tekton.dev/release: "devel"
    version: "devel"
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: controller
      app.kubernetes.io/component: controller
      app.kubernetes.io/instance: default
      app.kubernetes.io/part-of: tekton-chains
  template:
    metadata:
      annotations:
        cluster-autoscaler.kubernetes.io/safe-to-evict: "false"
      labels:
        app: tekton-chains-controller
        app.kubernetes.io/name: controller
        app.kubernetes.io/component: controller
        app.kubernetes.io/instance: default
        app.kubernetes.io/part-of: tekton-chains
        # # tekton.dev/release value replaced with inputs.params.versionTag in pipeline/tekton/publish.yaml
        pipeline.tekton.dev/release: "devel"
        version: "devel"
    spec:
      serviceAccountName: tekton-chains-controller
      initContainers:
        - name: download-sigstore-kms-venafi-plugin
          image: alpine:latest
          command:
            - sh
            - -c
          args:
            - echo Downloading Venafi KMS Plugin for Sigstore;
              wget -O /venafi-plugin/sigstore-kms-venafi https://github.com/Venafi/sigstore-kms-venafi/releases/download/v0.1.0-rc1/sigstore-kms-venafi-linux-amd64;
              chmod 755 /venafi-plugin/sigstore-kms-venafi;
              echo Finished downloading;
          volumeMounts:
          - mountPath: /venafi-plugin
            name: venafi-plugin
      containers:
        - name: tekton-chains-controller
          image: ko://github.com/tektoncd/chains/cmd/controller
          volumeMounts:
            - name: signing-secrets
              mountPath: /etc/signing-secrets
            - name: oidc-info
              mountPath: /var/run/sigstore/cosign
            - name: venafi-plugin
              mountPath: /usr/bin/sigstore-kms-venafi
              subPath: sigstore-kms-venafi
          env:
            - name: SYSTEM_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
            - name: METRICS_DOMAIN
              value: tekton.dev/chains
            - name: CONFIG_OBSERVABILITY_NAME
              value: tekton-chains-config-observability
            - name: CONFIG_LEADERELECTION_NAME
              value: tekton-chains-config-leader-election
            - name: VSIGN_URL
              value: <!--https://tpp.example.local-->
            - name: VSIGN_TOKEN
              valueFrom:
                secretKeyRef:
                  name: venaficsp
                  key: token

          ports:
            - name: metrics
              containerPort: 9090
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            # User 65532 is the distroless nonroot user ID
            runAsUser: 65532
            runAsGroup: 65532
      volumes:
        - name: venafi-plugin
          emptyDir: {}
        - name: signing-secrets
          secret:
            secretName: signing-secrets
        - name: oidc-info
          projected:
            sources:
              # The "public good" instance supports tokens from EKS and GKE by default.
              # The fulcio URL can also be redirected to an instance that has been
              # configured to accept other issuers as well.  Removing this volume
              # completely will direct chains to use alternate ambient credentials
              # (e.g. GKE workload identity, SPIFFE)
              - serviceAccountToken:
                  path: oidc-token
                  expirationSeconds: 600 # Use as short-lived as possible.
                  audience: sigstore

```

3. Create a simple `TaskRun`

```bash
kubectl create -f https://raw.githubusercontent.com/tektoncd/chains/main/examples/taskruns/task-output-image.yaml
```

Wait for it to finish (all the steps should be marked as **Completed**).

Next, retrieve the signature and payload from the object (they are stored as base64-encoded annotations):

```bash
export TASKRUN_UID=$(tkn tr describe --last -o  jsonpath='{.metadata.uid}')
tkn tr describe --last -o jsonpath="{.metadata.annotations.chains\.tekton\.dev/signature-taskrun-$TASKRUN_UID}" | base64 -d > sig
```

Finally, we can check the signature with [cosign](https://github.com/sigstore/cosign):

```bash
cosign verify-blob-attestation --insecure-ignore-tlog --key venafi://container-signing-project\\my-cert  --signature sig --type slsaprovenance --check-claims=false /dev/null
Verified OK
```
