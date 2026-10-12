package main

// collector 代理（monitor-collector :7505，附录A 已运行的采集器）
import (
	"encoding/json"
	"net/http"
	"time"
)

var collectorBase = envOr("MODSAFE_COLLECTOR_URL", "http://127.0.0.1:7505")

func collectorGet(path string) (map[string]interface{}, error) {
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(collectorBase + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func collectorAlive() bool {
	_, err := collectorGet("/summary")
	return err == nil
}
