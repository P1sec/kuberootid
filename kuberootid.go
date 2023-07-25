package main

// TODO
// - Container name
// - Detect root when `id` not in path ?
//   * With cat : /proc/$$/status ( grep -e "^Uid:" -e "^Gid:" /proc/$$/status )

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

    clientset, err := kubernetes.NewForConfig(kubeConfig)
    if err != nil {
        fmt.Printf("error getting kubernetes config: %v\n", err)
        os.Exit(1)
    }
    return clientset, kubeConfig
}

func main() {
    clientset, config := getKubernetesClient()

    vulns_pods_count := 0

    pods, err := ListPods(clientset)
    if err != nil {
        fmt.Println(err.Error)
        os.Exit(1)
    }

    fmt.Printf("%-20s %-50s %-50s %-10s\n", "Namespace", "Pod name", "Owner Name", "Owner Kind")

    var namespace string
    for _, pod := range pods.Items {
        namespace = pod.ObjectMeta.Namespace
        is_root, err := podExec(namespace, pod.Name, clientset, config)

        if err != nil {
            fmt.Printf("Could not verify %v: %v\n", pod.Name, err)
            continue
        }  
        if is_root {
            vulns_pods_count++
            if len(pod.OwnerReferences) > 0 {
                owner := pod.OwnerReferences[0]
                ownerName := owner.Name
                ownerKind := owner.Kind
                if owner.Kind == "ReplicaSet" {
                   upperOwner, ok := findReplicaSetOwner(namespace, owner, clientset)
                   if ok {
                     ownerName = upperOwner.Name
                     ownerKind = upperOwner.Kind
                   }
                }
                fmt.Printf("%-20s %-50s %-50s %-10s\n", pod.Namespace, pod.Name, ownerName, ownerKind)
            } else {
                fmt.Printf("%-20s %-50s\n", pod.Namespace, pod.Name)
            }
        }
    }
    fmt.Printf("Total pods vulnerable: %d\n", vulns_pods_count)
}


func findReplicaSetOwner(namespace string, ownerRef metav1.OwnerReference, client kubernetes.Interface) (*metav1.OwnerReference, bool) {
    replicaSet, err := client.AppsV1().ReplicaSets(namespace).Get(context.TODO(), ownerRef.Name, metav1.GetOptions{})
    if err != nil {
        fmt.Println(err.Error)
        os.Exit(1)
    }
    
    if len(replicaSet.OwnerReferences) > 0 {
        ownerOfOwnerRef := replicaSet.OwnerReferences[0]
        return &ownerOfOwnerRef, true
    }
    return nil, false
}

func ListPods(client kubernetes.Interface) (*v1.PodList, error) {
    pods, err := client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
    if err != nil {
        err = fmt.Errorf("error getting pods: %v\n", err)
        return nil, err
    }
    return pods, nil
}


func podExec(namespace string, podName string, client kubernetes.Interface, config *rest.Config) (bool, error) {

    pod, err := client.CoreV1().Pods(namespace).Get(context.Background(), podName, metav1.GetOptions{})
    if err != nil {
        panic(err)
    }

    containers := pod.Spec.Containers
    for _, container := range containers {
        req := client.CoreV1().RESTClient().Post().
            Namespace(namespace).
            Resource("pods").
            Name(podName).
            SubResource("exec").
            VersionedParams(&v1.PodExecOptions{
                Container: container.Name,
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
    }
    return false, err
}