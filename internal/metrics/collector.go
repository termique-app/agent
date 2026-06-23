package metrics

import (
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

// Snapshot holds a point-in-time reading of CPU, RAM, and disk metrics.
type Snapshot struct {
	CpuPercent    float64 `json:"cpu_percent"`
	RamPercent    float64 `json:"ram_percent"`
	RamUsedBytes  uint64  `json:"ram_used_bytes"`
	RamTotalBytes uint64  `json:"ram_total_bytes"`
	DiskPercent   float64 `json:"disk_percent"`
	DiskUsedBytes uint64  `json:"disk_used_bytes"`
	DiskTotalBytes uint64 `json:"disk_total_bytes"`
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

	return &Snapshot{
		CpuPercent:     cpuPct,
		RamPercent:     vmStat.UsedPercent,
		RamUsedBytes:   vmStat.Used,
		RamTotalBytes:  vmStat.Total,
		DiskPercent:    diskStat.UsedPercent,
		DiskUsedBytes:  diskStat.Used,
		DiskTotalBytes: diskStat.Total,
	}, nil
}
