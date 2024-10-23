package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Struct to parse the Kubernetes Node Metrics API JSON
type NodeMetrics struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Usage struct {
			CPU    string `json:"cpu"`
			Memory string `json:"memory"`
		} `json:"usage"`
	} `json:"items"`
}

// Struct to parse the Kubernetes Pod Metrics API JSON
type PodMetrics struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Containers []struct {
			Name  string `json:"name"`
			Usage struct {
				CPU    string `json:"cpu"`
				Memory string `json:"memory"`
			} `json:"usage"`
		} `json:"containers"`
	} `json:"items"`
}

var (
	// Metrics for node CPU and memory
	nodeCPU = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubernetes_node_cpu_usage_millicores",
			Help: "CPU usage in millicores for Kubernetes nodes",
		},
		[]string{"node"},
	)

	nodeMemory = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubernetes_node_memory_usage_bytes",
			Help: "Memory usage in bytes for Kubernetes nodes",
		},
		[]string{"node"},
	)

	// Metrics for pod CPU and memory
	podCPU = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubernetes_pod_cpu_usage_millicores",
			Help: "CPU usage in millicores for Kubernetes pods",
		},
		[]string{"namespace", "pod", "container"},
	)

	podMemory = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubernetes_pod_memory_usage_bytes",
			Help: "Memory usage in bytes for Kubernetes pods",
		},
		[]string{"namespace", "pod", "container"},
	)
)

func init() {
	// Register Prometheus metrics for both nodes and pods
	prometheus.MustRegister(nodeCPU)
	prometheus.MustRegister(nodeMemory)
	prometheus.MustRegister(podCPU)
	prometheus.MustRegister(podMemory)
}

// Helper function to get the token from the service account in the Kubernetes cluster
func getToken() (string, error) {
	// Path to the token file in a Kubernetes Pod
	tokenFile := "./token"
	data, err := ioutil.ReadFile(tokenFile)
	if err != nil {
		return "", fmt.Errorf("could not read token file: %v", err)
	}
	return string(data), nil
}

// Helper function to perform an HTTP request with Bearer token and return the response
func getMetricsFromAPI(apiPath string) ([]byte, error) {
	// Get the Bearer token
	token, err := getToken()
	if err != nil {
		return nil, err
	}

	// Create an HTTP client that skips certificate verification (for self-signed certs)
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Make an HTTP GET request to the Kubernetes API
	req, err := http.NewRequest("GET", apiPath, nil)
	if err != nil {
		return nil, err
	}

	// Add the Bearer token for authentication
	req.Header.Add("Authorization", "Bearer "+token)

	// Execute the request
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// Function to collect node metrics from Kubernetes API
func collectNodeMetrics() {
	apiPath := "http://18.224.169.142:8080/apis/metrics.k8s.io/v1beta1/nodes" // Replace localhost with your API server URL

	// Get the metrics from the API
	body, err := getMetricsFromAPI(apiPath)
	if err != nil {
		log.Printf("Error getting node metrics: %v", err)
		return
	}

	// Parse the JSON response
	var metrics NodeMetrics
	err = json.Unmarshal(body, &metrics)
	if err != nil {
		log.Printf("Error parsing node metrics: %v", err)
		return
	}

	for _, item := range metrics.Items {
		cpuValue := parseCPU(item.Usage.CPU)
		memoryValue := parseMemory(item.Usage.Memory)

		nodeCPU.WithLabelValues(item.Metadata.Name).Set(cpuValue)
		nodeMemory.WithLabelValues(item.Metadata.Name).Set(memoryValue)
	}
}

// Function to collect pod metrics from Kubernetes API
func collectPodMetrics() {
	apiPath := "http://18.224.169.142:8080/apis/metrics.k8s.io/v1beta1/pods" // Replace localhost with your API server URL

	// Get the metrics from the API
	body, err := getMetricsFromAPI(apiPath)
	if err != nil {
		log.Printf("Error getting pod metrics: %v", err)
		return
	}

	// Parse the JSON response
	var metrics PodMetrics
	err = json.Unmarshal(body, &metrics)
	if err != nil {
		log.Printf("Error parsing pod metrics: %v", err)
		return
	}

	for _, item := range metrics.Items {
		for _, container := range item.Containers {
			cpuValue := parseCPU(container.Usage.CPU)
			memoryValue := parseMemory(container.Usage.Memory)

			podCPU.WithLabelValues(item.Metadata.Namespace, item.Metadata.Name, container.Name).Set(cpuValue)
			podMemory.WithLabelValues(item.Metadata.Namespace, item.Metadata.Name, container.Name).Set(memoryValue)
		}
	}
}

// Helper function to parse CPU values (millicores)
func parseCPU(cpu string) float64 {
	cpu = strings.TrimSuffix(cpu, "m")
	parsedValue, _ := strconv.ParseFloat(cpu, 64)
	return parsedValue
}

// Helper function to parse memory values (bytes)
func parseMemory(memory string) float64 {
	memory = strings.ToLower(memory)
	var multiplier float64

	if strings.HasSuffix(memory, "ki") {
		memory = strings.TrimSuffix(memory, "ki")
		multiplier = 1024
	} else if strings.HasSuffix(memory, "mi") {
		memory = strings.TrimSuffix(memory, "mi")
		multiplier = 1024 * 1024
	} else if strings.HasSuffix(memory, "gi") {
		memory = strings.TrimSuffix(memory, "gi")
		multiplier = 1024 * 1024 * 1024
	} else {
		multiplier = 1
	}

	parsedValue, _ := strconv.ParseFloat(memory, 64)
	return parsedValue * multiplier
}

// Metrics handler
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	collectNodeMetrics()
	collectPodMetrics()
	promhttp.Handler().ServeHTTP(w, r)
}

func main() {
	http.Handle("/metrics", http.HandlerFunc(metricsHandler))
	fmt.Println("Starting metrics exporter on port 8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
