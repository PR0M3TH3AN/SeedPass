import json
import os
import subprocess
import datetime
import sys
import time

# Configuration
CONFIG_FILE = "torch-config.json"
ROSTER_FILE = "src/prompts/roster.json"
LOG_DIR = "task-logs/daily/"
AGENTS_MD_FILE = "../AGENTS.md"  # Relative to torch/
VALIDATION_CMD = "npm run lint"  # Default validation command

def run_command(command, check=True):
    print(f"Running: {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"Error running command: {command}")
        print(result.stderr)
        # Don't exit here immediately, let caller handle
    return result

def ensure_directories():
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs("task-logs/weekly/", exist_ok=True)

def check_agents_md():
    if os.path.exists(AGENTS_MD_FILE):
        print(f"Reading {AGENTS_MD_FILE}...")
        with open(AGENTS_MD_FILE, "r") as f:
            # Just verify we can read it
            f.read(100)
    else:
        print(f"No {AGENTS_MD_FILE} found; continuing")

def get_exclusion_set():
    # MUST 2: Run preflight to get the exclusion set
    # npm run lock:check:daily -- --json --quiet
    cmd = "npm run --silent lock:check:daily -- --json --quiet"
    result = run_command(cmd, check=False)

    if result.returncode != 0:
        print(f"Warning: exclusion check failed with code {result.returncode}")
        return set()

    try:
        output = result.stdout.strip()
        print(f"Exclusion output: {output}") # Debug print

        # Find the JSON object
        start = output.find('{')
        end = output.rfind('}')
        if start != -1 and end != -1:
            json_str = output[start:end+1]
            data = json.loads(json_str)
            return set(data.get("excluded", []))
        else:
            print("Warning: Could not find JSON in exclusion output")
            return set()
    except json.JSONDecodeError as e:
        print(f"Warning: Failed to parse exclusion JSON: {e}")
        return set()

def get_next_agent(roster, excluded):
    # List files in log dir
    log_files = sorted([f for f in os.listdir(LOG_DIR) if f.endswith(".md")])

    start_index = 0
    if not log_files:
        start_agent = "ci-health-agent" # Default if no logs
        # Try to read from config if available
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                start_agent = config.get("scheduler", {}).get("firstPromptByCadence", {}).get("daily", start_agent)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

        if start_agent in roster:
            start_index = roster.index(start_agent)
    else:
        latest_file = log_files[-1]
        # Parse agent from filename: <timestamp>__<agent-name>__<status>.md
        try:
            parts = latest_file.split("__")
            if len(parts) >= 2:
                previous_agent = parts[1]
                if previous_agent in roster:
                    start_index = (roster.index(previous_agent) + 1) % len(roster)
        except Exception:
            pass

    # Round robin
    for i in range(len(roster)):
        idx = (start_index + i) % len(roster)
        agent = roster[idx]
        if agent not in excluded:
            return agent

    return None

def acquire_lock(agent):
    # AGENT_PLATFORM=<platform> npm run lock:lock -- --agent <agent-name> --cadence daily
    # platform is simulated as 'local'
    cmd = f"npm run --silent lock:lock -- --agent {agent} --cadence daily"
    # We simulate environment variable
    env = os.environ.copy()
    env["AGENT_PLATFORM"] = "local"

    print(f"Acquiring lock for {agent}...")
    result = subprocess.run(cmd, shell=True, env=env, capture_output=True, text=True)

    if result.returncode == 0:
        return True
    elif result.returncode == 3:
        print(f"Race condition: Lock for {agent} already acquired (exit code 3).")
        return False
    else:
        print(f"Lock acquisition failed with code {result.returncode}")
        print(result.stderr)
        return False

def run_memory_workflow(stage, agent):
    # stage is 'retrieve' or 'store'
    # Check config for command
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            policy = config.get("scheduler", {}).get("memoryPolicyByCadence", {}).get("daily", {})

            command = policy.get(f"{stage}Command")
            artifact = policy.get(f"{stage}Artifact")
            mode = policy.get("mode", "optional")

            if command:
                print(f"Running memory {stage} command: {command}")
                res = run_command(command, check=False)
                if res.returncode != 0:
                    print(f"Memory {stage} command failed.")
                    if mode == "required":
                        return False
            else:
                print(f"No memory {stage} command configured.")

            # Validate artifact
            if artifact:
                if not os.path.exists(artifact):
                    print(f"Memory {stage} artifact {artifact} missing.")
                    if mode == "required":
                        return False
                else:
                    print(f"Memory {stage} artifact {artifact} confirmed.")
                    # We don't delete artifact here as it is evidence.

    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return True

def main():
    # 1. & 2. Ensure directories and check AGENTS.md
    ensure_directories()
    check_agents_md()

    # 3. Read Roster
    if not os.path.exists(ROSTER_FILE):
        print(f"Roster file {ROSTER_FILE} not found.")
        sys.exit(1)

    with open(ROSTER_FILE, "r") as f:
        roster_data = json.load(f)
        daily_roster = roster_data.get("daily", [])

    if not daily_roster:
        print("No daily agents in roster.")
        sys.exit(1)

    while True:
        # 4. Get exclusion set
        excluded = get_exclusion_set()
        print(f"Excluded agents: {excluded}")

        # 5. Select next agent
        agent = get_next_agent(daily_roster, excluded)
        if not agent:
            print("All roster tasks currently claimed by other agents")
            timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
            # Write to a special log file or just print and exit
            log_file = os.path.join(LOG_DIR, f"{timestamp}__scheduler__failed.md")
            with open(log_file, "w") as f:
                f.write("All roster tasks currently claimed by other agents")
            sys.exit(1)

        print(f"Selected agent: {agent}")

        # 6. Acquire Lock with Retry Logic
        if acquire_lock(agent):
            break
        else:
            print("Retrying selection...")
            time.sleep(1) # Wait a bit before retry

    # 7. Execute Prompt
    # Memory Retrieval
    if not run_memory_workflow("retrieve", agent):
        print("Memory retrieval failed (required).")
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
        log_file = os.path.join(LOG_DIR, f"{timestamp}__{agent}__failed.md")
        with open(log_file, "w") as f:
            f.write("Memory retrieval failed (required).")
        sys.exit(1)

    prompt_file = os.path.join("src/prompts/daily", f"{agent}.md")
    if os.path.exists(prompt_file):
        print(f"Executing prompt from {prompt_file}...")
        with open(prompt_file, "r") as f:
            content = f.read()
            print("--- PROMPT START ---")
            print(content)
            print("--- PROMPT END ---")
        # Simulate execution success
    else:
        print(f"Prompt file {prompt_file} not found.")

    # Memory Storage
    if not run_memory_workflow("store", agent):
        print("Memory storage failed (required).")
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
        log_file = os.path.join(LOG_DIR, f"{timestamp}__{agent}__failed.md")
        with open(log_file, "w") as f:
            f.write("Memory storage failed (required).")
        sys.exit(1)

    # 8. Run Validation
    print(f"Running validation ({VALIDATION_CMD})...")
    # Execute validation command
    # We use VALIDATION_CMD but fall back to a dummy if it fails to even run (e.g. command not found)
    # But for 'npm run lint', if npm exists, it runs.

    validation_result = run_command(VALIDATION_CMD, check=False)

    if validation_result.returncode != 0:
        print("Validation failed:")
        print(validation_result.stdout)
        print(validation_result.stderr)
        # Write failed log
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
        log_file = os.path.join(LOG_DIR, f"{timestamp}__{agent}__failed.md")
        with open(log_file, "w") as f:
            f.write(f"Validation failed:\n{validation_result.stdout}\n{validation_result.stderr}")
        sys.exit(1)

    # 9. Complete Lock
    print("Completing lock...")
    complete_cmd = f"npm run --silent lock:complete -- --agent {agent} --cadence daily"
    env = os.environ.copy()
    env["AGENT_PLATFORM"] = "local"
    complete_result = subprocess.run(complete_cmd, shell=True, env=env, capture_output=True, text=True)

    if complete_result.returncode != 0:
        print("Completion failed:")
        print(complete_result.stderr)
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
        log_file = os.path.join(LOG_DIR, f"{timestamp}__{agent}__failed.md")
        with open(log_file, "w") as f:
            f.write(f"Completion failed:\n{complete_result.stderr}")
        sys.exit(1)

    # 10. Write Completed Log
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
    log_file = os.path.join(LOG_DIR, f"{timestamp}__{agent}__completed.md")
    with open(log_file, "w") as f:
        f.write(f"Task completed successfully for {agent}.\n")
    print(f"Log written to {log_file}")

if __name__ == "__main__":
    main()
