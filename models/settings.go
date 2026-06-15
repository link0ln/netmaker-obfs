package models

type Theme string

const (
	Dark   Theme = "dark"
	Light  Theme = "light"
	System Theme = "system"
)

type ServerSettings struct {
	NetclientAutoUpdate bool     `json:"netclientautoupdate"`
	Verbosity           int32    `json:"verbosity"`
	AuthProvider        string   `json:"authprovider"`
	OIDCIssuer          string   `json:"oidcissuer"`
	ClientID            string   `json:"client_id"`
	ClientSecret        string   `json:"client_secret"`
	SyncEnabled         bool     `json:"sync_enabled"`
	GoogleAdminEmail    string   `json:"google_admin_email"`
	GoogleSACredsJson   string   `json:"google_sa_creds_json"`
	AzureTenant         string   `json:"azure_tenant"`
	OktaOrgURL          string   `json:"okta_org_url"`
	OktaAPIToken        string   `json:"okta_api_token"`
	UserFilters         []string `json:"user_filters"`
	GroupFilters        []string `json:"group_filters"`
	IDPSyncInterval     string   `json:"idp_sync_interval"`
	Telemetry           string   `json:"telemetry"`
	BasicAuth           bool     `json:"basic_auth"`
	// JwtValidityDuration is the validity duration of auth tokens for users
	// on the dashboard (NMUI).
	JwtValidityDuration int `json:"jwt_validity_duration"`
	// JwtValidityDurationClients is the validity duration of auth tokens for
	// users on the clients (NetDesk).
	JwtValidityDurationClients int    `json:"jwt_validity_duration_clients"`
	MFAEnforced                bool   `json:"mfa_enforced"`
	RacRestrictToSingleNetwork bool   `json:"rac_restrict_to_single_network"`
	EndpointDetection          bool   `json:"endpoint_detection"`
	AllowedEmailDomains        string `json:"allowed_email_domains"`
	EmailSenderAddr            string `json:"email_sender_addr"`
	EmailSenderUser            string `json:"email_sender_user"`
	EmailSenderPassword        string `json:"email_sender_password"`
	SmtpHost                   string `json:"smtp_host"`
	SmtpPort                   int    `json:"smtp_port"`
	MetricInterval             string `json:"metric_interval"`
	MetricsPort                int    `json:"metrics_port"`
	// IPDetectionInterval is the interval (in seconds) at which devices check for changes in public ip.
	IPDetectionInterval            int    `json:"ip_detection_interval"`
	ManageDNS                      bool   `json:"manage_dns"`
	DefaultDomain                  string `json:"default_domain"`
	Stun                           bool   `json:"stun"`
	StunServers                    string `json:"stun_servers"`
	AuditLogsRetentionPeriodInDays int    `json:"audit_logs_retention_period"`
	PeerConnectionCheckInterval    string `json:"peer_connection_check_interval"`
	PostureCheckInterval           string `json:"posture_check_interval"` // in minutes
	CleanUpInterval                int    `json:"clean_up_interval_in_mins"`
	EnableFlowLogs                 bool   `json:"enable_flow_logs"`
	// AmneziaWG holds the global AmneziaWG DPI-obfuscation parameters. They are
	// delivered identically to every host (one WG interface per host is shared
	// across networks, so the obfuscation framing must match on all peers).
	AmneziaWG AmneziaWGConfig `json:"amneziawg"`
	// AutoRelayEnabled turns on automatic relay fallback: hosts detected behind a
	// symmetric NAT (which cannot UDP hole-punch) are automatically routed through
	// the AutoRelayNodeID node. AutoRelayNodeID must be a Linux node with a public
	// endpoint, designated by the admin (e.g. via the gateway API).
	AutoRelayEnabled bool   `json:"auto_relay_enabled"`
	AutoRelayNodeID  string `json:"auto_relay_node_id"`
}

// AmneziaWGConfig - global AmneziaWG DPI-obfuscation parameters. When Enabled is
// false, all values are ignored and the dataplane behaves as vanilla WireGuard.
// H1-H4 are uint32 magic headers (as strings, optionally a "start-end" range) that
// replace the standard WireGuard message types 1/2/3/4. Jc/Jmin/Jmax control junk
// packets; S1-S4 control packet padding. I1-I5 (AWG 1.5) are not yet wired.
type AmneziaWGConfig struct {
	Enabled bool   `json:"awg_enabled" yaml:"awg_enabled"`
	Jc      int    `json:"awg_jc" yaml:"awg_jc"`
	Jmin    int    `json:"awg_jmin" yaml:"awg_jmin"`
	Jmax    int    `json:"awg_jmax" yaml:"awg_jmax"`
	S1      int    `json:"awg_s1" yaml:"awg_s1"`
	S2      int    `json:"awg_s2" yaml:"awg_s2"`
	S3      int    `json:"awg_s3" yaml:"awg_s3"`
	S4      int    `json:"awg_s4" yaml:"awg_s4"`
	H1      string `json:"awg_h1" yaml:"awg_h1"`
	H2      string `json:"awg_h2" yaml:"awg_h2"`
	H3      string `json:"awg_h3" yaml:"awg_h3"`
	H4      string `json:"awg_h4" yaml:"awg_h4"`
	// I1-I5 (AWG 1.5) are optional init-packet obfuscation chains in amneziawg's
	// tag DSL, e.g. "<b 0xc0ffee><r 16><t>" (tags: b/t/r/rc/rd/d/ds/dz). Empty =
	// AWG 1.0 behaviour. Passed through verbatim; the dataplane validates them.
	I1 string `json:"awg_i1" yaml:"awg_i1"`
	I2 string `json:"awg_i2" yaml:"awg_i2"`
	I3 string `json:"awg_i3" yaml:"awg_i3"`
	I4 string `json:"awg_i4" yaml:"awg_i4"`
	I5 string `json:"awg_i5" yaml:"awg_i5"`
}

type UserSettings struct {
	Theme         Theme  `json:"theme"`
	TextSize      string `json:"text_size"`
	ReducedMotion bool   `json:"reduced_motion"`
}
