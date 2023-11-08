package monitor

import (
    "github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus"
    "net/http"
    "runtime"
    "time"
    "github.com/shirou/gopsutil/cpu"
)


var (
    AssertionSize = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{ // gauge - registro unico,constantemente mudando a cada gather
            Name: "assertion_size_bytes", // tamanho das asserções em bytes ( anon - schnorr )
            Help: "Size of the assertion in bytes.", //descrição para aparecer na prometheusUI 9090
        },
        []string{}, // separar por qual método de chamada
    )
)

var (
    CpuUsage = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "app_cpu_usage_percentage",
            Help: "Current CPU usage percentage of the application.",
        },
    )
)

var (
    MemoryUsage = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "app_memory_usage_bytes",
            Help: "Current memory usage of the application in bytes.",
        },
    )
)


var (
    SVIDCertSize = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{ // gauge - registro unico,constantemente mudando a cada gather
            Name: "svid_cert_size_bytes", // tamanho das asserções em bytes ( anon - schnorr )
            Help: "Size of the svid certificates in bytes.", //descrição para aparecer na prometheusUI 9090
        },
        []string{}, // separar por qual método de chamada
    )
)

var (
    ExecutionTimeSummary = prometheus.NewSummaryVec( // TimeTrack instrumentalizado para processos
        prometheus.SummaryOpts{
            Name:       "execution_time_summary_seconds", // summary - registro somatório,constantemente concatenando a cada gather
            Help:       "Execution time summary of various methods in seconds",  //descrição para aparecer na prometheusUI 9090
        },
        []string{"method"}, // Add labels to differentiate different methods
    )
)

func UpdateCPUUsage() {
    for {
        percentages, err := cpu.Percent(1*time.Second, false)
        if err == nil && len(percentages) > 0 {
            // Update the cpuUsage metric with the current CPU usage percentage
            CpuUsage.Set(percentages[0])
        }

        // Sleep for a specific interval (e.g., 1 minute)
        time.Sleep(10 * time.Millisecond)
    }
}

func UpdateMemoryUsage() {
    for {
        var m runtime.MemStats
        runtime.ReadMemStats(&m)

        // Update the memoryUsage metric with the current memory usage in bytes
        MemoryUsage.Set(float64(m.Alloc))

        // Sleep for a specific interval (e.g., 1 minute)
        time.Sleep(10 * time.Millisecond)
    }
}


func RegisterMetrics() {
    defaultRegistry := prometheus.NewRegistry()
    prometheus.DefaultRegisterer = defaultRegistry
    prometheus.DefaultGatherer = defaultRegistry
    prometheus.MustRegister(MemoryUsage)
    prometheus.MustRegister(CpuUsage)
    prometheus.MustRegister(AssertionSize) // Métrica de tamanho de asserção sendo registrada como metrica custom
    prometheus.MustRegister(ExecutionTimeSummary) // Métrica de runtime dos processos sendo registrados como metrica custom
    prometheus.MustRegister(SVIDCertSize)
}

func PrometheusAPI(){
	http.Handle("/metrics", promhttp.Handler())
    http.ListenAndServe(":2110", nil)
}


