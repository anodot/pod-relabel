package k8s

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestJsonMapping(t *testing.T) {
	mapping := PodsMapping{
		WhitelistedPods: NewCache(),
		ExcludedPods:    NewCache(),
	}

	mapping.ExcludedPods.Store(SaveEntry{
		Name:      "alert-cfg-reporter-1579498200-qnnr6",
		Labels:    map[string]string{"anodot.com/podName": "alert-cfg-reporter-1579411800-0", "2": "3"},
		Namespace: "default",
	})
	mapping.WhitelistedPods.Store(SaveEntry{
		Name:      "alert-cfg-reporter-1579498200-qnnr6",
		Labels:    map[string]string{"anodot.com/podName": "alert", "2": "3"},
		Namespace: "system",
	})

	marshal, err := json.Marshal(mapping)
	if err != nil {
		t.Fatal(err)
	}

	expctedRes := `{"WhitelistedPods":{"Data":{"system|alert-cfg-reporter-1579498200-qnnr6":"alert"}},"ExcludedPods":{"Data":{"default|alert-cfg-reporter-1579498200-qnnr6":"alert-cfg-reporter-1579411800-0"}}}`
	excptedBytes := []byte(expctedRes)

	if !reflect.DeepEqual(marshal, excptedBytes) {
		t.Fatal("not exqual")
	}
}
