#!/usr/bin/env bash
set -euo pipefail
kubectl apply -f ./k8s/
aws ecs update-service --cluster prod --service api --force-new-deployment
