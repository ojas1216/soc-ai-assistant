import json

def summarize_sysmon(sysmon_file="sample_inputs/sysmon_log.json"):
    try:
        with open(sysmon_file) as f:
            logs = json.load(f)
        events = []
        for log in logs[:10]:
            event = f"Time: {log.get('TimeCreated')} | Process: {log.get('Process')} | Command: {log.get('CommandLine')}"
            events.append(event)
        return "\n".join(events)
    except Exception as e:
        return f"Error reading Sysmon log: {str(e)}"

def summarize_pcap(pcap_file="sample_inputs/sample_pcap_summary.txt"):
    try:
        with open(pcap_file) as f:
            return f.read()
    except:
        return "No PCAP summary available."
