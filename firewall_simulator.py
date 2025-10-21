
import json
import ipaddress
from datetime import datetime

# -----------------------------
# Load firewall rules from JSON
# -----------------------------
def load_rules(filename="rules.json"):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print("❌ Error: rules.json not found.")
        return []
    except json.JSONDecodeError:
        print("❌ Error: Invalid JSON format in rules.json.")
        return []

# ---------------------------------------------------
# Function to check if a source IP matches rule subnet
# ---------------------------------------------------
def ip_matches(source_ip, rule_ip):
    try:
        return ipaddress.ip_address(source_ip) in ipaddress.ip_network(rule_ip, strict=False)
    except ValueError:
        return False

# -------------------------------------------
# Main firewall logic: evaluate a packet input
# -------------------------------------------
def check_packet(source_ip, port, protocol, rules):
    for rule in rules:
        if (
            ip_matches(source_ip, rule["source_ip"])
            and int(port) == int(rule["port"])
            and protocol.upper() == rule["protocol"].upper()
        ):
            timestamp = datetime.now().strftime("%H:%M:%S")
            action = "🟢 ALLOWED" if rule["action"].lower() == "allow" else "🔴 BLOCKED"
            return (
                f"{action} (Rule ID: {rule['id']})\n"
                f"Description: {rule['description']}\n"
                f"Time: {timestamp}"
            )

    # Default action: block if no rule matches
    return "⚪ No matching rule found → DEFAULT ACTION: BLOCKED"

# ----------------------
# Main interactive logic
# ----------------------
def main():
    print("\n=== 🧱 Simple Firewall Rule Simulator ===")
    rules = load_rules()

    if not rules:
        print("No rules loaded. Exiting.")
        return

    while True:
        print("\nEnter packet details (type 'exit' to quit)\n")
        src_ip = input("Source IP: ").strip()
        if src_ip.lower() == "exit":
            print("👋 Exiting Firewall Simulator.")
            break

        try:
            port = int(input("Destination Port: ").strip())
        except ValueError:
            print("⚠️ Invalid port number. Try again.")
            continue

        protocol = input("Protocol (TCP/UDP): ").strip().upper()
        if protocol not in ["TCP", "UDP"]:
            print("⚠️ Invalid protocol. Enter TCP or UDP.")
            continue

        result = check_packet(src_ip, port, protocol, rules)
        print("\n" + "=" * 50)
        print(result)
        print("=" * 50)

if __name__ == "__main__":
    main()
