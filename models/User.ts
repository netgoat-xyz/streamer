import mongoose from "mongoose";

const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  image: String,
  role: { type: String, default: "user" },
  banned: { type: Boolean, default: false },

  // Optional legacy agent credentials. They are never exposed by /users;
  // the agent snapshot only becomes authoritative when explicit settings opt
  // in and every active user has a credential hash.
  password_hash: String,
  zero_trust_enabled: { type: Boolean, default: true },

  experiments: [String],
  
  // Domain tracking
  domain_count: { type: Number, default: 0 },
  max_domains: { type: Number, default: 5 }, // Quota limit
  
  // Stats
  total_bandwidth: { type: Number, default: 0 },
  total_requests: { type: Number, default: 0 },

  createdAt: Date,
  updatedAt: Date
}, { collection: "user" }); 

// Virtual for checking if user can add more domains
UserSchema.virtual('can_add_domain').get(function() {
  return this.domain_count < this.max_domains;
});

export default mongoose.models.User || mongoose.model("User", UserSchema);
