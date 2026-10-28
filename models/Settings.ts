import mongoose from "mongoose";

const SettingsSchema = new mongoose.Schema({
  // Legacy key/value settings are retained for backward-compatible reads.
  key: { type: String },
  value: { type: mongoose.Schema.Types.Mixed },
  siteName: { type: String, default: "NetGoat" },
  registrationEnabled: { type: Boolean, default: true },
  maintenanceMode: { type: Boolean, default: false },

  sentryEnabled: { type: Boolean, default: false },
  sentryDsn: { type: String, default: "" },

  proEnabled: { type: Boolean, default: false },
  dnsEnabled: { type: Boolean, default: true },
  reverseProxyEnabled: { type: Boolean, default: true },
  zeroTrustEnabled: { type: Boolean, default: false },
  casEnabled: { type: Boolean, default: false },
  // The agent can only replace its local users when the control plane makes
  // that ownership explicit. These remain opt-in because dashboard users and
  // agent login users may be managed independently.
  agentUsersConfigured: { type: Boolean, default: false },
  agentUserDomainsConfigured: { type: Boolean, default: false },
  // Plugin deployment is independently authoritative. The stream server
  // publishes a bounded, execution-free installation plan only when this flag
  // is true; an explicit empty plan safely removes prior global installs.
  pluginsConfigured: { type: Boolean, default: false },
  plugins: {
    type: mongoose.Schema.Types.Mixed,
    default: () => ({ installations: [] }),
  },

  userDomainLimit: { type: Number, default: 3 },
  dnsRecordLimit: { type: Number, default: 50 },
  organizationLimit: { type: Number, default: 1 },
  auditLogRetentionDays: { type: Number, default: 30 },

  globalBannerEnabled: { type: Boolean, default: false },
  globalBannerText: { type: String, default: "" },
  globalBannerVariant: { 
    type: String, 
    default: "info", 
    enum: ["info", "warning", "error", "success", "announcement", "marketing", "rainbow", "midnight"] 
  },

  featureFlags: [{
    key: String,
    description: String,
    isActive: { type: Boolean, default: false }, 
    percentage: { type: Number, default: 0 },
    variants: [String]
  }],

  agentConfig: {
    type: mongoose.Schema.Types.Mixed,
    default: () => ({})
  }
}, { timestamps: true });

export default mongoose.models.Settings || mongoose.model("Settings", SettingsSchema);
