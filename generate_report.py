import os
import csv
from datetime import datetime
from supabase import create_client, Client

# Initialize credentials
SUPABASE_URL = os.environ.get("SUPABASE_URL") or "https://qwsnkbpsumqobrqkqpht.supabase.co"
SUPABASE_KEY = os.environ.get("SUPABASE_KEY") or "sb_publishable_IPKGvB9I6G7Ix0q2kkpucw_8JdGDaHh"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def fetch_historical_metrics():
    print("[Analytics Engine] Querying historical network streams from Supabase...")
    try:
        # Pull all log records ordered by latest entry
        response = supabase.table("network_logs").select("*").order("created_at", descending=True).execute()
        return response.data
    except Exception as e:
        print(f"[Analytics Error] Failed to retrieve logs: {e}")
        return []

def generate_csv_report(data, filename):
    if not data:
        return
    
    keys = data[0].keys()
    with open(filename, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data)
    print(f"[Analytics Engine] Raw database history successfully exported to spreadsheet: {filename}")

def generate_summary_analytics(data, filename):
    if not data:
        print("[Analytics Engine] No historical entries found to compile analytics.")
        return

    total_streams = len(data)
    model_counts = {}
    total_input = 0
    total_output = 0

    for row in data:
        model = row.get("model_name", "Unknown")
        model_counts[model] = model_counts.get(model, 0) + 1
        total_input += int(row.get("input_tokens") or 0)
        total_output += int(row.get("output_tokens") or 0)

    # Compile a beautiful summary overview
    report_md = f"""# Advanced AI Proxy — Token Matrix Executive Report
**Generated On:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
---

## ## High-Level Summary Metrics
* **Total Streams Intercepted:** {total_streams}
* **Cumulative Input Tokens Transmitted:** {total_input}
* **Cumulative Output Tokens Received:** {total_output}
* **Aggregate Volumetric Token Traffic:** {total_input + total_output}

---

## ## Model Distribution Analytics
| Model Infrastructure Group | Requests Handled | Utilization % |
| :--- | :---: | :---: |
"""
    for model, count in model_counts.items():
        percentage = round((count / total_streams) * 100, 2)
        report_md += f"| **{model}** | {count} | {percentage}% |\n"

    with open(filename, mode='w', encoding='utf-8') as f:
        f.write(report_md)
    print(f"[Analytics Engine] Executive text intelligence report compiled: {filename}")

if __name__ == "__main__":
    records = fetch_historical_metrics()
    
    if records:
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Output reports
        generate_csv_report(records, f"historical_matrix_data_{timestamp_str}.csv")
        generate_summary_analytics(records, f"executive_analytics_summary_{timestamp_str}.md")
    else:
        print("[Analytics Engine] Setup empty or unable to access database records.")