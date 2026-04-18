package constants

// Database Configuration Keys
const (
	ConfigWifiInterface   = "WIFI_INTERFACE"
	ConfigMonitorIface    = "MONITOR_INTERFACE"
	ConfigUplinkInterface = "UPLINK_INTERFACE"
	ConfigInternalNet     = "INTERNAL_NET"
	ConfigInternalIP      = "INTERNAL_IP"
	ConfigGuestSSID       = "GUEST_SSID"
	ConfigGuestBSSID      = "GUEST_BSSID"
	ConfigGuestChannel    = "GUEST_CHANNEL"
	ConfigSessionID       = "SESSION_ID"
	ConfigSessionName     = "SESSION_NAME"
	ConfigManagementIface = "MANAGEMENT_INTERFACE"
	ConfigScopeBSSIDs     = "SCOPE_BSSIDS"
)

// Module Reqs
const (
	ReqMonitorIface = "monitor_iface"
	ReqManagedIface = "managed_iface"
	ReqNAT          = "nat"
)

// Statuses
const (
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusNotRun    = "not_run"
)

// Finding Types
const (
	FindingVulnerability = "vulnerability"
	FindingCredential    = "credential"
)

// TUI Colors (ANSI)
const (
	ColorReset  = "\033[0m"
	ColorBold   = "\033[1m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorGray   = "\033[90m"
)

// Themed Colors
const (
	ThemeCritical = ColorBold + ColorRed
	ThemeHigh     = ColorRed
	ThemeMedium   = ColorYellow
	ThemeInfo     = ColorCyan
	ThemeSuccess  = ColorGreen
	ThemeHeader   = ColorBold + ColorWhite
	ThemeMission  = "\033[1;35m" // Bold Magenta
)
