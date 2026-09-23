// From internal/config/config.go - The load() function that initializes all config variables
// This is the single source of truth for how each configuration value is parsed, bounded, and defaulted.

func load(observer loader.Observer) {
	Enabled = loader.BoolFromEnv(observer, EnvVarEnabled, true)
	RequestSamplingPct = int(loader.UintFromEnvBounded(observer, EnvVarRequestSampling, 30, uint8(0), uint8(100)))
	MaxConcurrentRequests = int(loader.UintFromEnvBounded(observer, EnvVarMaxConcurrentRequests, uint64(2), uint8(0), uint8(64)))
	VulnerabilitiesPerRequest = int(loader.UintFromEnvBounded(observer, EnvVarVulnerabilitiesPerRequest, 2, uint64(1), uint64(MaxVulnerabilitiesPerRequest)))
	DeduplicationEnabled = loader.BoolFromEnv(observer, EnvVarDeduplicationEnabled, true)
	RedactionEnabled = loader.BoolFromEnv(observer, EnvVarRedactionEnabled, true)
	RedactionNamePattern = loader.FromEnvWithFallback(observer, EnvVarRedactionNamePattern, EnvVarRedactionKeysRegexp, defaultRedactionNamePattern, parser.ParseRegexp)
	RedactionValuePattern = loader.FromEnvWithFallback(observer, EnvVarRedactionValuePattern, EnvVarRedactionValuesRegexp, defaultRedactionValuePattern, parser.ParseRegexp)
	TruncationMaxValue = loader.UintFromEnv(observer, EnvVarTruncationMaxValue, 250)
	MaxRangeCount = loader.UintFromEnvBounded(observer, EnvVarMaxRangeCount, uint64(ranges.DefaultLimit), uint64(1), uint64(ranges.HardLimit))
	TelemetryVerbosity = loader.FromEnv(observer, EnvVarTelemetryVerbosity, LogLevelInformation, parser.ParseLogLevel)
	DbRowsToTaint = loader.UintFromEnv(observer, EnvVarDbRowsToTaint, 1)
	StackTraceEnabled = loader.BoolFromEnv(observer, EnvVarStackTraceEnabled, true)
}

// Constants defined in config.go:
const (
	MaxVulnerabilitiesPerRequest = 64
)

// ranges.go constants:
const (
	DefaultLimit = 10  // MaxRangeCount default
	HardLimit = 64     // MaxRangeCount maximum
)
