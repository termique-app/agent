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
	RamCachedBytes uint64  `json:"ram_cached_bytes"`
	RamFreeBytes   uint64  `json:"ram_free_bytes"`
	SwapUsedBytes  uint64  `json:"swap_used_bytes"`
	SwapTotalBytes uint64  `json:"swap_total_bytes"`
	SwapPercent    float64 `json:"swap_percent"`
	DiskPercent    float64 `json:"disk_percent"`
	DiskUsedBytes  uint64  `json:"disk_used_bytes"`
	DiskTotalBytes uint64  `json:"disk_total_bytes"`
	DiskDevice     string  `json:"disk_device"`
	DiskMountpoint string  `json:"disk_mountpoint"`
	DiskFstype     string  `json:"disk_fstype"`
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

	// Swap is optional — systems without swap (or where the read fails) report
	// zeroes rather than failing the whole snapshot.
	var swapUsed, swapTotal uint64
	var swapPct float64
	if swapStat, serr := mem.SwapMemory(); serr == nil {
		swapUsed = swapStat.Used
		swapTotal = swapStat.Total
		swapPct = swapStat.UsedPercent
	}

	// Device name for the root mount (e.g. /dev/vda1). disk.Usage already gives
	// us the filesystem type; the device name needs the partition table.
	device := ""
	fstype := diskStat.Fstype
	if parts, perr := disk.Partitions(false); perr == nil {
		for _, p := range parts {
			if p.Mountpoint == "/" {
				device = p.Device
				if p.Fstype != "" {
					fstype = p.Fstype
				}
				break
			}
		}
	}

	return &Snapshot{
		CpuPercent:     cpuPct,
		RamPercent:     vmStat.UsedPercent,
		RamUsedBytes:   vmStat.Used,
		RamTotalBytes:  vmStat.Total,
		RamCachedBytes: vmStat.Cached,
		RamFreeBytes:   vmStat.Free,
		SwapUsedBytes:  swapUsed,
		SwapTotalBytes: swapTotal,
		SwapPercent:    swapPct,
		DiskPercent:    diskStat.UsedPercent,
		DiskUsedBytes:  diskStat.Used,
		DiskTotalBytes: diskStat.Total,
		DiskDevice:     device,
		DiskMountpoint: "/",
		DiskFstype:     fstype,
		UptimeSeconds:  uptimeSec,
	}, nil
}
