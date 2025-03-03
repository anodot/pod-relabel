package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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
)

var (
	// TODO: check
	cacheMissed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "anodot_kubernetes_pod_cache_missed",
		Help: "Number of time cache missed",
	})
	// TODO: check
	cacheFillTime = promauto.NewSummary(prometheus.SummaryOpts{
		Name:       "anodot_kubernetes_cache_fill_time_ms",
		Help:       "CAHNGE-me",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
	})

	podIDNotFoundCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pod_relabel_id_not_found_count",
			Help: "pod_id not found",
		},
		[]string{"namespace"},
	)
)

const (
	allNamespaces         = ""
	excludeNamespaceParam = "EXCLUDE_NAMESPACE"
	includeNamespaceParam = "INCLUDE_NAMESPACE"

	AnodotPodNameLabel string = "anodot.com/podName"
)

var StatefulPodRegex = regexp.MustCompile("(.*)-([0-9]+)$")

type NamespaceFilter interface {
	IsAllowed(namespace string) bool
	String() string
}

type IncludeNamespaceFilter struct {
	namespaces map[string]bool
}

type ExcludeNamespaceFilter struct {
	namespaces map[string]bool
}

func NewIncludeNamespaceFilter(namespaceList string) *IncludeNamespaceFilter {
	filter := &IncludeNamespaceFilter{
		namespaces: make(map[string]bool),
	}

	for _, ns := range strings.Split(namespaceList, ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			filter.namespaces[ns] = true
		}
	}

	return filter
}

func (f *IncludeNamespaceFilter) IsAllowed(namespace string) bool {
	if len(f.namespaces) == 0 {
		return false
	}

	return f.namespaces[namespace]
}

func (f *IncludeNamespaceFilter) String() string {
	names := make([]string, 0, len(f.namespaces))
	for name := range f.namespaces {
		names = append(names, name)
	}
	return fmt.Sprintf("Include:[%s]", strings.Join(names, ","))
}

func NewExcludeNamespaceFilter(namespaceList string) *ExcludeNamespaceFilter {
	filter := &ExcludeNamespaceFilter{
		namespaces: make(map[string]bool),
	}

	for _, ns := range strings.Split(namespaceList, ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			filter.namespaces[ns] = true
		}
	}

	return filter
}

func (f *ExcludeNamespaceFilter) IsAllowed(namespace string) bool {
	if len(f.namespaces) == 0 {
		return true
	}

	// Any namespace not in map is allowed
	return !f.namespaces[namespace]
}

func (f *ExcludeNamespaceFilter) String() string {
	names := make([]string, 0, len(f.namespaces))
	for name := range f.namespaces {
		names = append(names, name)
	}
	return fmt.Sprintf("Exclude:[%s]", strings.Join(names, ","))
}

// Factory func to create ns filter
func CreateNamespaceFilter(includeNamespaces, excludeNamespaces string) (NamespaceFilter, error) {
	if includeNamespaces != "" && excludeNamespaces != "" {
		return nil, fmt.Errorf("only one of %s or %s can be specified, not both", includeNamespaceParam, excludeNamespaceParam)
	}

	if includeNamespaces != "" {
		return NewIncludeNamespaceFilter(includeNamespaces), nil
	}

	// Default to exclude
	return NewExcludeNamespaceFilter(excludeNamespaces), nil
}

type PodsMapping struct {
	WhitelistedPods *PodCache
	ExcludedPods    *PodCache
}

type config struct {
	podLabelSelector labels.Selector
	namespaceFilter  NamespaceFilter
	watchNamespace   string
	stopCh           chan struct{}

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

	// parse
	namespace := r.URL.Query().Get("namespace")
	podID := r.URL.Query().Get("pod_id")

	// if pod_id is specified return as plain text
	if podID != "" {
		// We need an explicit namespace parameter for all pod lookups
		if namespace == "" {
			klog.V(4).Infof("pod lookup failed: missing namespace parameter for pod %s", podID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Check in whitelisted pods
		podName := c.includedPods.Lookup(SearchEntry{
			PodName:   podID,
			Namespace: namespace,
		})

		if podName != "" {
			w.Header().Set("Content-Type", "application/json")
			jsonBytes, err := json.Marshal(podName)
			if err != nil {
				klog.Errorf("Error marshaling JSON: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_, err = w.Write(jsonBytes)
			if err != nil {
				klog.Errorf("Error writing response: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		// Pod not found
		klog.V(4).Infof("pod not found: %s in namespace %s", podID, namespace)

		// metric
		podIDNotFoundCounter.WithLabelValues(namespace).Inc()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Default case: return full JSON response
	w.Header().Set("Content-Type", "application/json")

	// If no filters specified, return full map
	if namespace == "" {
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
			klog.Errorf("Error writing response: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Filter by namespace only
	result := make(map[string]interface{})
	whitelistedPods := make(map[string]string)
	excludedPods := make(map[string]string)

	// Filter whitelisted pods
	for k, v := range c.includedPods.Data {
		ns, _ := k.GetPodNameAndNamespace()
		if ns == namespace {
			whitelistedPods[string(k)] = v
		}
	}

	// Filter excluded pods
	for k, v := range c.excludePods.Data {
		ns, _ := k.GetPodNameAndNamespace()
		if ns == namespace {
			excludedPods[string(k)] = v
		}
	}

	result["namespace"] = namespace
	result["whitelistedPods"] = whitelistedPods
	result["excludedPods"] = excludedPods

	bytes, err := json.Marshal(result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	klog.V(5).Info(string(bytes))
	_, err = w.Write(bytes)
	if err != nil {
		klog.Errorf("Error writing response: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func NewPodRelabel(apiClient *kubernetes.Clientset, excludeNamespaces, includeNamespaces, includeLabels string, notify chan bool) (*config, error) {
	selector, err := labels.Parse(includeLabels)
	if err != nil {
		return nil, fmt.Errorf("invalid label selector: %w", err)
	}

	// Create namespace filter
	nsFilter, err := CreateNamespaceFilter(includeNamespaces, excludeNamespaces)
	if err != nil {
		return nil, err
	}

	return &config{
		podLabelSelector: selector,
		namespaceFilter:  nsFilter,
		includedPods:     NewCache(),
		excludePods:      NewCache(),
		mu:               sync.Mutex{},
		apiClient:        apiClient,
		notify:           notify,
	}, nil
}

func (c *config) Start() {
	ctx := context.Background()

	// watch first from INCLUDE_NAMESPACE if not empty, else allNamespaces
	watchNamespace := allNamespaces
	if includeFilter, ok := c.namespaceFilter.(*IncludeNamespaceFilter); ok {
		if len(includeFilter.namespaces) > 0 {
			for ns := range includeFilter.namespaces {
				watchNamespace = ns
				klog.V(2).Infof("watching namespace '%s' based on INCLUDE_NAMESPACE", watchNamespace)
				break
			}
		}
	}

	klog.V(2).Infof("starting pod relabel, labelsSelector='%s', namespaceFilter='%s', watching namespace='%s'",
		c.podLabelSelector, c.namespaceFilter.String(), watchNamespace)
	c.watchNamespace = watchNamespace
	c.startInformer(ctx)
	c.startPeriodicJob(ctx)
}

func (c *config) startInformer(ctx context.Context) {
	watchlist := cache.NewListWatchFromClient(
		c.apiClient.CoreV1().RESTClient(),
		"pods",
		c.watchNamespace,
		fields.Everything(),
	)

	cacheWatchList := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			klog.V(4).Infof("listing pods in namespace '%s'", c.watchNamespace)
			return watchlist.List(options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			klog.V(4).Infof("watching pods in namespace '%s'", c.watchNamespace)
			return watchlist.Watch(options)
		},
	}

	_, controller := cache.NewInformer(cacheWatchList, &corev1.Pod{}, 0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				pod := obj.(*corev1.Pod)
				klog.V(2).Infof("pod added: '%s' in namespace '%s'", pod.Name, pod.Namespace)
				err := c.doHandle(ctx, c.apiClient, pod)
				if err != nil {
					klog.Error(err.Error())
				}
			},
			DeleteFunc: func(obj interface{}) {
				pod := obj.(*corev1.Pod)
				klog.V(2).Infof("pod deleted: '%s' in namespace '%s'", pod.Name, pod.Namespace)
				c.includedPods.Delete(SearchEntry{Namespace: pod.Namespace, PodName: pod.Name})
			},
		},
	)

	stop := make(chan struct{})
	c.stopCh = stop
	go controller.Run(stop)
}

func (c *config) startPeriodicJob(ctx context.Context) {
	go func() {
		for {
			time.Sleep(5 * time.Minute)

			klog.V(2).Infof("running periodic check for unlabeled pods in namespace '%s'", c.watchNamespace)

			//select only pods which does not have AnodotPodNameLabel
			list, err := c.apiClient.CoreV1().Pods(c.watchNamespace).List(ctx, metav1.ListOptions{
				LabelSelector: fmt.Sprintf("!%s", AnodotPodNameLabel),
			})

			if err != nil {
				klog.Errorf("error listing pods: %v", err)
				continue
			}

			// for _, p := range list.Items {
			//      // err := c.doHandle(c.apiClient, &p)
			//      err := c.doHandle(ctx, c.apiClient, obj.(*corev1.Pod))
			//      if err != nil {
			//              klog.Error(err)
			//      }
			// }
			klog.V(2).Infof("found %d pods that do not have %q label in namespace '%s'",
				len(list.Items), AnodotPodNameLabel, c.watchNamespace)

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
}

func (c *config) doHandle(ctx context.Context, apiClient *kubernetes.Clientset, pod *corev1.Pod) error {
	klog.V(4).Infof("processing pod %q in namespace %q ", pod.Name, pod.Namespace)

	// Check if the pod namespace is allowed by filter
	if !c.namespaceFilter.IsAllowed(pod.Namespace) {
		klog.V(4).Infof("pod %s is in filtered namespace %s", pod.Name, pod.Namespace)
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
