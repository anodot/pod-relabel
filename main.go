package main

import (
	"flag"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog"
	"log"
	"net/http"
	"os"
	"pod-labes-setter/pkg/k8s"
)

func main() {
	klog.InitFlags(nil)
	flag.Set("v", os.Getenv("LOG_LEVEL"))
	flag.Parse()

	exludeNsStr := os.Getenv("EXCLUDE_NAMESPACE")
	labelsSelectorStr := os.Getenv("INCLUDE_LABELS")

	//refreshConfig := make(chan bool, 1)
	notify := make(chan bool)

	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		klog.Fatal(err)
	}

	client, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		klog.Fatal(err)
	}

	podWatcher, err := k8s.NewPodRelabel(client, exludeNsStr, labelsSelectorStr, notify)
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
