package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"pod-labes-setter/pkg/k8s"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog"
)

func main() {
	klog.InitFlags(nil)
	flag.Set("v", os.Getenv("LOG_LEVEL"))
	flag.Parse()

	excludeNsStr := os.Getenv("EXCLUDE_NAMESPACE")
	includeNsStr := os.Getenv("INCLUDE_NAMESPACE")
	labelsSelectorStr := os.Getenv("INCLUDE_LABELS")

	notify := make(chan bool)

	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		klog.Fatal(err)
	}

	client, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		klog.Fatal(err)
	}

	podWatcher, err := k8s.NewPodRelabel(client, excludeNsStr, includeNsStr, labelsSelectorStr, notify)
	if err != nil {
		klog.Fatalf("Failed to initialize k8s pod watcher. Error: %s", err.Error())
	}

	podWatcher.Start()

	http.Handle("/pods", podWatcher)
	log.Fatal(http.ListenAndServe(":8080", nil))

	/*
		for {
			select {
			case _ = <-refreshConfig:
				//podWatcher.AvailablePods()
			}
		}*/
}
