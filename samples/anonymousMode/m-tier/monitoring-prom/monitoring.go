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
        prometheus.GaugeOpts{ // gauge - registro unico,constantemente mudando a cada gather
            Name: "app_cpu_usage_percentage", // uso de CPU em porcentagem
            Help: "Current CPU usage percentage of the application.", //descrição para aparecer na prometheusUI 9090
        },
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


var (
    MemoryUsage = prometheus.NewGauge(
        prometheus.GaugeOpts{ // gauge - registro unico,constantemente mudando a cada gather
            Name: "app_memory_usage_bytes", // uso de memória (armazenamento em bytes)
            Help: "Current memory usage of the application in bytes.",   //descrição para aparecer na prometheusUI 9090
        },
    )
)


func UpdateCPUUsage() { // Funcao p/ atualizar a metrica de uso de cpu em %
    for {
        percentages, err := cpu.Percent(100*time.Millisecond, false)
        if err == nil && len(percentages) > 0 {
            // atualizando o uso de cpu
            CpuUsage.Set(percentages[0])
        }

        // intervalo de medição
        time.Sleep(10 * time.Millisecond)
    }
}

func UpdateMemoryUsage() { // Funcao p/ atualizar a metrica de uso de memoria em bytes
    for {
        var m runtime.MemStats
        runtime.ReadMemStats(&m)

        MemoryUsage.Set(float64(m.Alloc))

        // intervalo de medição
        time.Sleep(10 * time.Millisecond)
    }
}



func RegisterMetrics() { // Função para registro das metricas no TSDB do Prometheus
    defaultRegistry := prometheus.NewRegistry()
    prometheus.DefaultRegisterer = defaultRegistry
    prometheus.DefaultGatherer = defaultRegistry
    prometheus.MustRegister(MemoryUsage) // Métrica de Memória sendo registrada como metrica custom
    prometheus.MustRegister(CpuUsage) // Métrica de CPU sendo registrada como metrica custom
    prometheus.MustRegister(AssertionSize) // Métrica de tamanho de asserção sendo registrada como metrica custom
    prometheus.MustRegister(ExecutionTimeSummary) // Métrica de runtime dos processos sendo registrados como metrica custom
}

func PrometheusAPI(){  
	http.Handle("/metrics", promhttp.Handler())  // exposição da API do prometheus para mandar os dados coletados
    http.ListenAndServe(":2115", nil)   // port diferente da utilizada para app
}


