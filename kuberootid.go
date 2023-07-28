package main

import (
    "context"
    "fmt"
    "strings"
    "bytes"
    "os"
    "path/filepath"

    "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/tools/clientcmd"
    "k8s.io/client-go/rest"
    "k8s.io/client-go/kubernetes/scheme"
    "k8s.io/client-go/tools/remotecommand"
)


func getKubernetesClient() (kubernetes.Interface, *rest.Config) {
    userHomeDir, err := os.UserHomeDir()
    if err != nil {
        fmt.Printf("error getting user home dir: %v\n", err)
        os.Exit(1)
    }
    kubeConfigPath := filepath.Join(userHomeDir, ".kube", "config")
    
    kubeConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)

    if err != nil {
        fmt.Printf("Error getting kubernetes config: %v\n", err)
        os.Exit(1)
    }

    client, err := kubernetes.NewForConfig(kubeConfig)
    if err != nil {
        fmt.Printf("error getting kubernetes config: %v\n", err)
        os.Exit(1)
    }
    return client, kubeConfig
}

func main() {
    client, config := getKubernetesClient()

    vulns_pods_count := 0
    vulns_container_count := 0
    total_pods := 0
    total_containers := 0

    pods, err := listPods(client)
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }

    fmt.Printf("%-20s %-50s %-20s %-50s %-10s\n", "Namespace", "Pod name", "Container", "Owner Name", "Owner Kind")

    var namespace string
    var found_container_root bool
    for _, pod := range pods.Items {
        namespace = pod.ObjectMeta.Namespace
        
        pod, err := client.CoreV1().Pods(namespace).Get(context.Background(), pod.Name, metav1.GetOptions{})
        if err != nil {
            panic(err)
        }

        containers := pod.Spec.Containers
        for _, container := range containers {
            total_containers++
            found_container_root = false
            is_root, err := isContainerRunningRoot(namespace, pod.Name, container.Name, client, config)
            if err != nil {
                fmt.Fprintf(os.Stderr, "Could not verify %v: %v\n", pod.Name, err)
                continue
            }
            if is_root {
                vulns_container_count++
                found_container_root = true
                if len(pod.OwnerReferences) > 0 {
                    ownerName, ownerKind := findOwner(pod, namespace, client)
                    fmt.Printf("%-20s %-50s %-20s %-50s %-10s\n", pod.Namespace, pod.Name, container.Name, ownerName, ownerKind)
                } else {
                    fmt.Printf("%-20s %-50s\n", pod.Namespace, pod.Name)
                }
            }
        }
        total_pods++
        if found_container_root {
            vulns_pods_count++
        }
    }
    fmt.Printf("Total containers: %d\n", total_containers)
    fmt.Printf("Containers runnig as root: %d\n", vulns_container_count)
    fmt.Printf("Total pods: %d\n", total_pods)
    fmt.Printf("Pods running with at least one container running root: %d\n", vulns_pods_count)
}

func findOwner(pod *v1.Pod, namespace string, client kubernetes.Interface) (string, string) {
    owner := pod.OwnerReferences[0]
    ownerName := owner.Name
    ownerKind := owner.Kind
    if owner.Kind == "ReplicaSet" {
       upperOwner, ok := findReplicaSetOwner(namespace, owner, client)
       if ok {
         ownerName = upperOwner.Name
         ownerKind = upperOwner.Kind
       }
    }
    return ownerName, ownerKind
}

func findReplicaSetOwner(namespace string, ownerRef metav1.OwnerReference, client kubernetes.Interface) (*metav1.OwnerReference, bool) {
    replicaSet, err := client.AppsV1().ReplicaSets(namespace).Get(context.TODO(), ownerRef.Name, metav1.GetOptions{})
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
    
    if len(replicaSet.OwnerReferences) > 0 {
        ownerOfOwnerRef := replicaSet.OwnerReferences[0]
        return &ownerOfOwnerRef, true
    }
    return nil, false
}

func listPods(client kubernetes.Interface) (*v1.PodList, error) {
    pods, err := client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
    if err != nil {
        err = fmt.Errorf("error getting pods: %v\n", err)
        return nil, err
    }
    return pods, nil
}


func isContainerRunningRoot(namespace string, podName string, containerName string, client kubernetes.Interface, config *rest.Config) (bool, error) {


    req := client.CoreV1().RESTClient().Post().
        Namespace(namespace).
        Resource("pods").
        Name(podName).
        SubResource("exec").
        VersionedParams(&v1.PodExecOptions{
            Container: containerName,
            Command:   []string{"id"},
            Stdout:    true,
            Stderr:    true,
            TTY:       false,
        }, scheme.ParameterCodec)

    exec, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
    if err != nil {
        panic(err)
    }

    var stdout, stderr bytes.Buffer
    err = exec.Stream(remotecommand.StreamOptions{
        Stdout: &stdout,
        Stderr: &stderr,
        Tty:    false,
    })

    output := stdout.String()

    if strings.Contains(output, "uid=0(root)") {
        return true, err
    }
    
    return false, err
}