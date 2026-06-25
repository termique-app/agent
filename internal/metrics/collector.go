package metrics

import (
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

// Snapshot holds a point-in-time reading of CPU, RAM, disk, and uptime metrics.
type Snapshot struct {
	CpuPercent     float64 `json:"cpu_percent"`
	RamPercent     float64 `json:"ram_percent"`
	RamUsedBytes   uint64  `json:"ram_used_bytes"`
	RamTotalBytes  uint64  `json:"ram_total_bytes"`
	DiskPercent    float64 `json:"disk_percent"`
	DiskUsedBytes  uint64  `json:"disk_used_bytes"`
	DiskTotalBytes uint64  `json:"disk_total_bytes"`
	UptimeSeconds  uint64  `json:"uptime_seconds"`
}

// Collect gathers a Snapshot. interval controls the CPU measurement window.
func Collect(interval time.Duration) (*Snapshot, error) {
	cpuPercents, err := cpu.Percent(interval, false)
	if err != nil {
		return nil, fmt.Errorf("metrics: cpu: %w", err)
	}
	var cpuPct float64
	if len(cpuPercents) > 0 {
		cpuPct = cpuPercents[0]
	}

	vmStat, err := mem.VirtualMemory()
	if err != nil {
		return nil, fmt.Errorf("metrics: memory: %w", err)
	}

	diskStat, err := disk.Usage("/")
	if err != nil {
		return nil, fmt.Errorf("metrics: disk: %w", err)
	}

	uptimeSec, err := host.Uptime()
	if err != nil {
		uptimeSec = 0
	}

	return &Snapshot{
		CpuPercent:     cpuPct,
		RamPercent:     vmStat.UsedPercent,
		RamUsedBytes:   vmStat.Used,
		RamTotalBytes:  vmStat.Total,
		DiskPercent:    diskStat.UsedPercent,
		DiskUsedBytes:  diskStat.Used,
		DiskTotalBytes: diskStat.Total,
		UptimeSeconds:  uptimeSec,
	}, nil
}
