# RBAC Walkthrough

This walkthrough demonstrate what is possible and not possible with RBAC enabled/disabled on different versions
of k8s using minikube

Please install minikube with the following instruction [https://kubernetes.io/docs/tasks/tools/install-minikube/](https://kubernetes.io/docs/tasks/tools/install-minikube/)

After you install minikube successfully let's go through running minikube with rbac disabled and see how easy it is to
jump from one pod (hacked pod) to another pod.

## without RBAC

```bash
minikube start --bootstrapper=localkube --kubernetes-version v1.9.4
```
Output:
```bash
Starting local Kubernetes v1.9.4 cluster...
Starting VM...
Getting VM IP address...
WARNING: The localkube bootstrapper is now deprecated and support for it
will be removed in a future release. Please consider switching to the kubeadm bootstrapper, which
is intended to replace the localkube bootstrapper. To disable this message, run
[minikube config set ShowBootstrapperDeprecationNotification false]
Moving files into cluster...
Setting up certs...
Connecting to cluster...
Setting up kubeconfig...
Starting cluster components...
Kubectl is now configured to use the cluster.
Loading cached images from config file.
``` 
```bash
kubectl config use-context minikube
kubectl run hello-minikube-1 --image=k8s.gcr.io/echoserver:1.4 --port=8080
kubectl run hello-minikube-2 --image=k8s.gcr.io/echoserver:1.4 --port=8080
```
Output:
```bash
Switched to context "minikube".
deployment "hello-minikube-1" created
deployment "hello-minikube-2" created
```
```bash
kubectl get pods
```
Output:
```bash
NAME                                READY     STATUS    RESTARTS   AGE
hello-minikube-1-6c755b6c96-dshjb   1/1       Running   0          1m
hello-minikube-2-68dc464676-26p25   1/1       Running   0          1m
```

Now let's bash in into one of the pods to illustrate a hacked pod.

```bash
kubectl exec -it hello-minikube-1-6c755b6c96-dshjb /bin/bash
```
Now the commands we run are inside hello-minikube-1 pod.

We can run commands against the k8s api server via curl and the token which is automounted
at `cat /run/secrets/kubernetes.io/serviceaccount/token` or via kubectl command.
In this tutorial we will use the latter as it is more convenient.

Download the kubectl:
```bash
apt update
apt install -y curl
curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
chmod +x ./kubectl
mv ./kubectl /usr/local/bin/kubectl
``` 

Now using the following command we can see that we actually have full access to k8s api server:

`kubectl get all`

if we get the following output then we are in business.

```bash
NAME                                    READY     STATUS    RESTARTS   AGE
pod/hello-minikube-1-6c755b6c96-dshjb   1/1       Running   0          8m
pod/hello-minikube-2-68dc464676-26p25   1/1       Running   0          8m
NAME                 TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
service/kubernetes   ClusterIP   10.96.0.1    <none>        443/TCP   11m
NAME                                     DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
deployment.extensions/hello-minikube-1   1         1         1            1           8m
deployment.extensions/hello-minikube-2   1         1         1            1           8m
NAME                                                DESIRED   CURRENT   READY     AGE
replicaset.extensions/hello-minikube-1-6c755b6c96   1         1         1         8m
replicaset.extensions/hello-minikube-2-68dc464676   1         1         1         8m
NAME                               DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/hello-minikube-1   1         1         1            1           8m
deployment.apps/hello-minikube-2   1         1         1            1           8m
NAME                                          DESIRED   CURRENT   READY     AGE
replicaset.apps/hello-minikube-1-6c755b6c96   1         1         1         8m
replicaset.apps/hello-minikube-2-68dc464676   1         1         1         8m
```

Now let's try to bash into hello-minikube-2

```bash
kubectl exec -it hello-minikube-2-68dc464676-26p25 /bin/bash
```
OUTPUT:
```bash
root@hello-minikube-2-68dc464676-26p25:/#
```
Boom. game over.

## with RBAC

Do all the above steps except the first step should be as follow:

`minikube start --bootstrapper=localkube --kubernetes-version v1.9.4 --extra-config=apiserver.Authorization.Mode=RBAC`

Now the output of the last command `kubectl get all`

should be:

```bash
Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:default:default" cannot list pods in the namespace "default"
Error from server (Forbidden): replicationcontrollers is forbidden: User "system:serviceaccount:default:default" cannot list replicationcontrollers in the namespace "default"
Error from server (Forbidden): services is forbidden: User "system:serviceaccount:default:default" cannot list services in the namespace "default"
Error from server (Forbidden): daemonsets.extensions is forbidden: User "system:serviceaccount:default:default" cannot list daemonsets.extensions in the namespace "default"
Error from server (Forbidden): deployments.extensions is forbidden: User "system:serviceaccount:default:default" cannot list deployments.extensions in the namespace "default"
Error from server (Forbidden): replicasets.extensions is forbidden: User "system:serviceaccount:default:default" cannot list replicasets.extensions in the namespace "default"
Error from server (Forbidden): daemonsets.apps is forbidden: User "system:serviceaccount:default:default" cannot list daemonsets.apps in the namespace "default"
Error from server (Forbidden): deployments.apps is forbidden: User "system:serviceaccount:default:default" cannot list deployments.apps in the namespace "default"
Error from server (Forbidden): replicasets.apps is forbidden: User "system:serviceaccount:default:default" cannot list replicasets.apps in the namespace "default"
Error from server (Forbidden): statefulsets.apps is forbidden: User "system:serviceaccount:default:default" cannot list statefulsets.apps in the namespace "default"
Error from server (Forbidden): horizontalpodautoscalers.autoscaling is forbidden: User "system:serviceaccount:default:default" cannot list horizontalpodautoscalers.autoscaling in the namespace "default"
Error from server (Forbidden): jobs.batch is forbidden: User "system:serviceaccount:default:default" cannot list jobs.batch in the namespace "default"
Error from server (Forbidden): cronjobs.batch is forbidden: User "system:serviceaccount:default:default" cannot list cronjobs.batch in the namespace "default"
```

We are secured:)

## Summary

Here is an awful long one-liner to check weather a given pod has rbac enabled/disabled and which read permissions it has
 
```bash
kubectl exec $(POD_NAME) -- bash -c apt update && apt install -y curl && curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl && chmod +x ./kubectl && mv ./kubectl /usr/local/bin/kubectl
```
