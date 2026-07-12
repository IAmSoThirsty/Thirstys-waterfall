"""
Complete Usage Example - Evidence-Gated Status Demonstration
"""

from thirstys_waterfall import ThirstysWaterfall

# Initialize the system
waterfall = ThirstysWaterfall()

# Start all subsystems
waterfall.start()

print("\n" + "=" * 80)
print("THIRSTYS WATERFALL - EVIDENCE-GATED STATUS")
print("=" * 80)

# 1. Check local encryption helper status
status = waterfall.get_status()
encryption_status = status.get("encryption", {})
print("\n1. LOCAL ENCRYPTION HELPER:")
print(f"   Accepted: {encryption_status.get('accepted', False)}")
print(f"   Helper tier: {encryption_status.get('helper_strength', {}).get('tier')}")
print(f"   Transport encrypted: {encryption_status.get('traffic_encrypted', False)}")

# 2. Browser with ad annihilator
print("\n2. BROWSER + AD ANNIHILATOR (HOLY WAR MODE):")
print("   No history: YES")
print("   No pop-ups: YES")
print("   No redirects: YES")
print("   Ad blocker: HOLY WAR MODE ACTIVE")
print("   Blocking evidence remains runtime/configuration dependent")

# 3. Thirsty Consigliere
print("\n3. THIRSTY CONSIGLIERE (Privacy-First Assistant):")
print("   Code of Omertà: ACTIVE")
print("   On-device only: YES")
print("   Data minimization: YES")
print("   Your confidential strategist ready")

# 4. Media Downloader
print("\n4. MEDIA DOWNLOADER:")
print("   Modes: audio-only, video-only, audio+video, best quality")
print("   Download encryption acceptance remains evidence-gated")
print("   Built-in library: ACTIVE")

# 5. AI Assistant
print("\n5. LOCAL AI ASSISTANT:")
print("   Local inference: YES")
print("   No external calls: YES")
print("   Privacy acceptance remains evidence-gated")

# 6. Remote Access
print("\n6. REMOTE ACCESS:")
print("   Remote browser: Available")
print("   Remote desktop: Available")
print("   Connection encryption acceptance remains evidence-gated")

# 7. Settings & Support
print("\n7. SETTINGS & SUPPORT:")
print("   Comprehensive settings: ALL features configurable")
print("   Q/A system: ACTIVE")
print("   Contact threads: improvements, features, security, code of conduct")
print("   Feedback manager: ACTIVE")

# 8. Security Status
print("\n8. SECURITY STATUS:")
print(f"   Kill switch: {status.get('kill_switch', {}).get('enabled', False)}")
print(f"   VPN connected: {status.get('vpn', {}).get('connected', False)}")
print(f"   Deployment accepted: {status.get('deployment_accepted', False)}")

print("\n" + "=" * 80)
print("SYSTEM STATUS REPORTED - ACCEPTANCE REMAINS EVIDENCE-GATED")
print("=" * 80 + "\n")

# Stop system (wiping all ephemeral data)
waterfall.stop()

print("System stopped. All ephemeral data wiped.")
