package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	cacheMissed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "anodot_kubernetes_pod_cache_missed",
		Help: "Number of time cache missed",
	})

	cacheFillTime = promauto.NewSummary(prometheus.SummaryOpts{
		Name:       "anodot_kubernetes_cache_fill_time_ms",
		Help:       "CAHNGE-me",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
	})
)

const (
	allNamespaces         = ""
	excludeNamespaceParam = "EXCLUDE_NAMESPACE"

	AnodotPodNameLabel string = "anodot.com/podName"
)

var StatefulPodRegex = regexp.MustCompile("(.*)-([0-9]+)$")

type excludeNSList map[string]bool

func NewExcludeNS(v string) excludeNSList {
	m := make(map[string]bool)
	for _, v := range strings.Split(v, ",") {
		m[v] = true
	}

	return m
}

type PodsMapping struct {
	WhitelistedPods *PodCache
	ExcludedPods    *PodCache
}

type config struct {
	podLabelSelector labels.Selector
	excludeNSList    excludeNSList

	includedPods *PodCache
	excludePods  *PodCache

	mu        sync.Mutex
	apiClient *kubernetes.Clientset

	notify chan bool
}

func (c *config) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	klog.V(5).Infof("received GET config request")

	defer r.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	mapping := PodsMapping{
		WhitelistedPods: c.includedPods,
		ExcludedPods:    c.excludePods,
	}

	bytes, err := json.Marshal(mapping)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	klog.V(5).Info(string(bytes))
	_, err = w.Write(bytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func NewPodRelabel(apiClinet *kubernetes.Clientset, excludeNamespaces string, includeLabels string, notify chan bool) (*config, error) {

	selector, err := labels.Parse(includeLabels)
	if err != nil {
		return nil, err
	}

	return &config{
		podLabelSelector: selector,
		excludeNSList:    NewExcludeNS(excludeNamespaces),
		includedPods:     NewCache(),
		excludePods:      NewCache(),
		mu:               sync.Mutex{},
		apiClient:        apiClinet,
		notify:           notify,
	}, nil

}

func (e excludeNSList) String() string {
	res := make([]string, len(e))
	for k := range e {
		res = append(res, k)
	}

	return strings.Join(res, ",")
}

func (c *config) Start() {
	ctx := context.Background()
	klog.V(2).Infof("starting pod re-label. labelsSelector='%s', namespaceIgnored='%s'", c.podLabelSelector, c.excludeNSList.String())
	watchlist := cache.NewListWatchFromClient(c.apiClient.CoreV1().RESTClient(), "pods", allNamespaces, fields.Everything())
	cacheWatchList := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return watchlist.List(options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return watchlist.Watch(options)
		},
	}

	go func() {
		for {
			time.Sleep(5 * time.Minute)
			//select only pods which does not have AnodotPodNameLabel
			list, err := c.apiClient.CoreV1().Pods(allNamespaces).List(ctx, metav1.ListOptions{LabelSelector: fmt.Sprintf("!%s", AnodotPodNameLabel)})

			if err != nil {
				klog.Error(err)
			}

			klog.V(4).Infof("found %d that does not have %q label", len(list.Items), AnodotPodNameLabel)

			// for _, p := range list.Items {
			// 	// err := c.doHandle(c.apiClient, &p)
			// 	err := c.doHandle(ctx, c.apiClient, obj.(*corev1.Pod))
			// 	if err != nil {
			// 		klog.Error(err)
			// 	}
			// }
			
			for _, p := range list.Items {
				err := c.doHandle(ctx, c.apiClient, &p)
				if err != nil {
					klog.Error(err)
				}
			}


			c.includedPods.PrintEntries()
			c.excludePods.PrintEntries()
		}
	}()

	_, controller := cache.NewInformer(cacheWatchList, &corev1.Pod{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				klog.V(4).Infof("pod added' %s'", obj.(*corev1.Pod).Name)
				err := c.doHandle(ctx, c.apiClient, obj.(*corev1.Pod))
				if err != nil {
					klog.Error(err.Error())
				}
			},
			DeleteFunc: func(obj interface{}) {
				pod := obj.(*corev1.Pod)
				klog.V(4).Infof("pod deleted' %s'", pod.Name)
				c.includedPods.Delete(SearchEntry{Namespace: pod.Namespace, PodName: pod.Name})
			},
		},
	)

	stop := make(chan struct{})
	go controller.Run(stop)
}

func (c *config) doHandle(ctx context.Context, apiClient *kubernetes.Clientset, pod *corev1.Pod) error {
	klog.V(4).Infof("processing pod %q in namespace %q ", pod.Name, pod.Namespace)

	if _, ignore := c.excludeNSList[pod.Namespace]; ignore {
		klog.V(4).Infof("pod %s is in exclude namespace list", pod.Name)
		c.excludePods.Store(SaveEntry{
			Name:        pod.Name,
			ChangedName: pod.Name,
			Namespace:   pod.Namespace,
		})
		return nil
	}

	if !c.podLabelSelector.Matches(labels.Set(pod.Labels)) {
		klog.V(4).Infof("pod %s does not match include labels list(%s)", pod.Name, c.podLabelSelector.String())
		c.excludePods.Store(SaveEntry{
			Name:        pod.Name,
			ChangedName: pod.Name,
			Namespace:   pod.Namespace,
		})
		return nil
	}

	if _, ok := pod.Labels[AnodotPodNameLabel]; ok {
		klog.V(4).Infof("label %s already set for pod %s", AnodotPodNameLabel, pod.Name)
		c.includedPods.Store(SaveEntry{
			Name:        pod.Name,
			ChangedName: pod.Labels[AnodotPodNameLabel],
			Namespace:   pod.Namespace,
		})
		return nil
	}

	if StatefulPodRegex.MatchString(pod.Name) {
		klog.V(4).Infof("skipping re-labeling pod (%s) which belongs to statefulset", pod.Name)
		c.includedPods.Store(SaveEntry{
			Name:        pod.Name,
			ChangedName: pod.Name,
			Namespace:   pod.Namespace,
		})
		return nil
	}

	podOwner := getPodOwner(ctx, apiClient, pod)
	if podOwner == nil {
		return nil
	}

	queryLabel := labels.SelectorFromSet(podOwner.selector).String()
	klog.V(4).Infof("searching pods by labels '%s'", queryLabel)

	c.mu.Lock()
	defer c.mu.Unlock()

	podList, err := apiClient.CoreV1().Pods(pod.Namespace).List(ctx, metav1.ListOptions{LabelSelector: queryLabel})
	if err != nil {
		return err
	}

	klog.V(5).Infof("found (%d)s matching queryLabel: %q", len(podList.Items), queryLabel)

	var ordinals []int
	for _, p := range podList.Items {
		//not in state terminating
		if p.DeletionTimestamp == nil {
			_, ordinal := getParentNameAndOrdinal(p.Labels[AnodotPodNameLabel])
			ordinals = append(ordinals, ordinal)
		}
	}
	sort.Ints(ordinals)
	maps := make(map[int]bool, len(ordinals))
	for _, o := range ordinals {
		maps[o] = true
	}

	var index int
FOR:
	for i := 0; i < math.MaxInt64; i++ {
		if _, ok := maps[i]; !ok {
			index = i
			break FOR
		}
	}

	if podOwner.name == "" {
		return fmt.Errorf("empty owner Name for pod=%s", pod.Name)
	}

	labelValue := fmt.Sprintf("%s-%d", podOwner.name, index)
	klog.V(5).Infof("setting '%s=%s' for pod '%s'", AnodotPodNameLabel, labelValue, pod.Name)

	newPod := pod.DeepCopy()
	if len(newPod.Labels) == 0 {
		newPod.Labels = map[string]string{AnodotPodNameLabel: labelValue}
	} else {
		newPod.Labels[AnodotPodNameLabel] = labelValue
	}

	oldData, err := json.Marshal(pod)
	if err != nil {
		return err
	}

	newData, err := json.Marshal(newPod)
	if err != nil {
		return err
	}

	patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldData, newData, corev1.Pod{})
	if err != nil {
		return err
	}

	klog.V(5).Infof("PATCH-BYTES: %q", string(patchBytes))

	updatedPod, err := apiClient.CoreV1().Pods(pod.Namespace).Patch(ctx, pod.Name, types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})
	if err != nil {
		return err
	}

	if _, ok := updatedPod.Labels[AnodotPodNameLabel]; ok {
		c.includedPods.Store(SaveEntry{
			Name:        updatedPod.Name,
			Namespace:   updatedPod.Namespace,
			ChangedName: updatedPod.Labels[AnodotPodNameLabel],
		})
	}

	return nil
}

func getPodOwner(ctx context.Context, apiClient *kubernetes.Clientset, pod *corev1.Pod) *podOwner {
    ownerReference := GetControllerOf(pod)
    if ownerReference == nil {
        klog.V(4).Infof("No owner reference for pod='%s'", pod.Name)
        return &podOwner{
            name:     pod.Name,
            selector: pod.Labels,
        }
    }

    klog.V(5).Infof("owner reference kind=%q with Name=%q", ownerReference.Kind, ownerReference.Name)

    if ownerReference.Kind == v1.SchemeGroupVersion.WithKind("ReplicaSet").Kind {
        klog.V(5).Infof("%q controlled by ReplicaSet", pod.Name)
        deploymentForPod := getDeploymentForPod(ctx, apiClient, pod)
        if deploymentForPod != nil {
            return &podOwner{
                name:     deploymentForPod.Name,
                selector: deploymentForPod.Spec.Selector.MatchLabels,
            }
        }
    } else if ownerReference.Kind == v1.SchemeGroupVersion.WithKind("DaemonSet").Kind {
        klog.V(5).Infof("%q controlled by DaemonSet", pod.Name)
        daemonSet := getDaemonSet(ctx, apiClient, pod)
        if daemonSet != nil {
            return &podOwner{
                name:     daemonSet.Name,
                selector: daemonSet.Spec.Selector.MatchLabels,
            }
        }
    } else if ownerReference.Kind == "Job" {
        // Handling for Job type if required
    } else {
        klog.V(4).Infof("Unsupported owner reference %q with Name %q", ownerReference.Kind, ownerReference.Name)
    }

    return nil
}

type podOwner struct {
	name     string
	selector map[string]string
}

func getDaemonSet(ctx context.Context, apiClient *kubernetes.Clientset, pod *corev1.Pod) *v1.DaemonSet {
	controllerRef := GetControllerOf(pod)
	// We can't look up by UID, so look up by Name and then verify UID.
	// Don't even try to look up by Name if it's the wrong Kind.
	if controllerRef.Kind != v1.SchemeGroupVersion.WithKind("DaemonSet").Kind {
		return nil
	}

	ds, err := apiClient.AppsV1().DaemonSets(pod.Namespace).Get(ctx, controllerRef.Name, metav1.GetOptions{})

	if err != nil {
		return nil
	}
	if ds.UID != controllerRef.UID {
		// The controller we found with this Name is not the same one that the
		// ControllerRef points to.
		return nil
	}
	return ds
}

func GetControllerOf(controllee metav1.Object) *metav1.OwnerReference {
	for _, ref := range controllee.GetOwnerReferences() {
		if ref.Controller != nil && *ref.Controller {
			return &ref
		}
	}
	return nil
}

func getDeploymentForPod(ctx context.Context, apiClient *kubernetes.Clientset, pod *corev1.Pod) *v1.Deployment {
	// Find the owning replica set
	var rs *v1.ReplicaSet
	var err error
	controllerRef := GetControllerOf(pod)
	if controllerRef == nil {
		klog.V(4).Infof("pod %q has no controller", pod.Name)
		return nil
	}
	if controllerRef.Kind != v1.SchemeGroupVersion.WithKind("ReplicaSet").Kind {
		klog.V(4).Infof("pod %q is not owned by replicaset", pod.Name)
		return nil
	}

	rs, err = apiClient.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, controllerRef.Name, metav1.GetOptions{})

	if err != nil || rs.UID != controllerRef.UID {
		klog.V(5).Infof("cannot get replicaset %q for pod %q: %v", controllerRef.Name, pod.Name, err)
		return nil
	}

	// Now find the Deployment that owns that ReplicaSet.
	controllerRef = GetControllerOf(rs)
	if controllerRef == nil {
		return nil
	}
	return resolveControllerRef(ctx, apiClient, rs.Namespace, controllerRef)
}

func resolveControllerRef(ctx context.Context, apiClient *kubernetes.Clientset, namespace string, controllerRef *metav1.OwnerReference) *v1.Deployment {
	// We can't look up by UID, so look up by Name and then verify UID.
	// Don't even try to look up by Name if it's the wrong Kind.
	if controllerRef.Kind != v1.SchemeGroupVersion.WithKind("Deployment").Kind {
		return nil
	}

	d, err := apiClient.AppsV1().Deployments(namespace).Get(ctx, controllerRef.Name, metav1.GetOptions{})

	if err != nil {
		return nil
	}
	if d.UID != controllerRef.UID {
		// The controller we found with this Name is not the same one that the
		// ControllerRef points to.
		return nil
	}
	return d
}

func getParentNameAndOrdinal(podName string) (string, int) {
	parent := ""
	ordinal := -1
	subMatches := StatefulPodRegex.FindStringSubmatch(podName)
	if len(subMatches) < 3 {
		return parent, ordinal
	}
	parent = subMatches[1]
	if i, err := strconv.ParseInt(subMatches[2], 10, 32); err == nil {
		ordinal = int(i)
	}
	return parent, ordinal
}