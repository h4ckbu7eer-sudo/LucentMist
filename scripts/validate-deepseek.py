"""Opt-in real-model validation. No credentials or request headers are persisted.

Set LMIST_LLM_APIKEY in the invoking process, then run with --output pointing to
an empty private temporary directory. The loopback recorder forwards only to
DeepSeek; it never substitutes model responses. Review transcripts before sharing.
"""
import argparse
import datetime
import http.server
import json
import locale
import os
from pathlib import Path
import re
import subprocess
import threading
import urllib.error
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("--output", required=True)
parser.add_argument("--mode", choices=["cli", "web"], default="cli")
parser.add_argument("--recorder-port", type=int, default=8357)
parser.add_argument("--api-port", type=int, default=5050)
parser.add_argument("--web-port", type=int, default=5051)
options = parser.parse_args()
secret = os.environ.get("LMIST_LLM_APIKEY", "")
if not secret:
    raise SystemExit("Set LMIST_LLM_APIKEY in the process environment first.")
output = Path(options.output).resolve()
if output.exists() and any(output.iterdir()):
    raise SystemExit("Use an empty output directory; do not mix independent verification runs.")
output.mkdir(parents=True, exist_ok=True)
root = Path(__file__).resolve().parents[1]
lock = threading.Lock()
run_label = options.mode


def clean(text):
    return re.sub(r"sk-[A-Za-z0-9_-]{16,}", "[REDACTED]", text.replace(secret, "[REDACTED]"))


def record(name, text):
    with lock:
        with (output / name).open("a", encoding="utf-8") as file:
            file.write(clean(text) + "\n")


class Recorder(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        if self.path != "/v1/chat/completions" or self.headers.get("Authorization") != "Bearer " + secret:
            self.send_error(403)
            return
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        request_data = json.loads(body)
        request = urllib.request.Request(
            "https://api.deepseek.com/v1/chat/completions", body,
            headers={"Authorization": "Bearer " + secret, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=95) as response:
                data = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            status, data = error.code, error.read()
        except Exception as error:
            status = 502
            data = json.dumps({"error": type(error).__name__}).encode()
        content = ""
        valid_json = valid_action = valid_input = False
        action = None
        try:
            content = json.loads(data)["choices"][0]["message"]["content"]
            step = json.loads(content)
            valid_json = isinstance(step, dict) and isinstance(step.get("thought"), str)
            action = step.get("action")
            prompt = request_data["messages"][-1]["content"]
            tools = set(re.findall(r'^- ([a-z_]+):', prompt.split("## 用户问题")[0], re.MULTILINE))
            valid_action = action == "final_answer" or action in tools
            value = step.get("action_input")
            valid_input = (isinstance(value, str) if action == "final_answer" else
                           isinstance(value, dict) or isinstance(value, str) and isinstance(json.loads(value), dict))
        except (ValueError, KeyError, TypeError, AttributeError, IndexError):
            pass
        record("model-responses.jsonl", json.dumps({
            "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "run": run_label,
            "httpStatus": status, "jsonValid": valid_json, "actionValid": valid_action,
            "inputValid": valid_input, "action": action, "content": content,
            "responseFormat": request_data.get("response_format"),
            "requestContext": request_data.get("messages", [])}, ensure_ascii=False))
        print(f"model run={run_label} HTTP={status} JSON={valid_json} action={action} allowed={valid_action} input={valid_input}", flush=True)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


server = http.server.ThreadingHTTPServer(("127.0.0.1", options.recorder_port), Recorder)
threading.Thread(target=server.serve_forever, daemon=True).start()
env = os.environ.copy()
env.update(LMIST_LLM_PROVIDER="deepseek", LMIST_LLM_MODEL="deepseek-chat",
           LMIST_LLM_ENDPOINT=f"http://127.0.0.1:{options.recorder_port}/v1", LMIST_DB=str(output / "validation.db"),
           LMIST_LOG_FILE=str(output / "application.log"), LMIST_INJECT_NETWORK_INFO="true",
           NO_PROXY="localhost,127.0.0.1,192.168.99.1", Logging__LogLevel__Default="Error")
children = []
cli_exits = []
try:
    if options.mode == "cli":
        for label, args, stdin in [
            ("ip", ["看看我的ip"], None),
            ("local", ["分析 127.0.0.1 的安全风险"], None),
            ("gateway", ["分析 192.168.99.1 的安全风险"], None),
            ("repl", [], "看看我的ip\n分析那个子网的网关\n/exit\n"),
        ]:
            run_label = label
            process = subprocess.Popen(["dotnet", str(root / "src/LucentMist.CLI/bin/Release/net10.0/lmist.dll"), "agent", *args],
                                       cwd=root, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT)
            children.append(process)
            try:
                stdout, _ = process.communicate(stdin.encode("utf-8") if stdin else None, timeout=600)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, _ = process.communicate()
            # Input is explicitly UTF-8 in Program.cs; Windows redirected output
            # still uses the host code page. Preserve readable, unmodified text.
            try:
                transcript = stdout.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                transcript = stdout.decode(locale.getpreferredencoding(False), errors="strict")
            record(label + ".txt", transcript.replace("\r\n", "\n"))
            cli_exits.append(process.returncode)
            print(f"CLI {label}: exit={process.returncode}; transcript={output / (label + '.txt')}", flush=True)
    else:
        for project, port in [("API", str(options.api_port)), ("Web", str(options.web_port))]:
            child_env = env.copy()
            if project == "Web":
                child_env.pop("LMIST_LLM_APIKEY", None)
                child_env["LMIST_API_URL"] = f"http://127.0.0.1:{options.api_port}"
                child_env["ASPNETCORE_CONTENTROOT"] = str(root / "src/LucentMist.Web")
                # A source-build host needs static-web-assets enabled. This is
                # a loopback-only development validation, not a published image.
                child_env["ASPNETCORE_ENVIRONMENT"] = "Development"
            process = subprocess.Popen(["dotnet", str(root / f"src/LucentMist.{project}/bin/Release/net10.0/LucentMist.{project}.dll"), port],
                                       cwd=root, env=child_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, encoding="utf-8", errors="replace")
            children.append(process)
            def drain(child=process, name=project):
                for line in child.stdout:
                    record(name + ".txt", line.rstrip())
            threading.Thread(target=drain, daemon=True).start()
        print(f"Web validation hosts launching on loopback {options.api_port}/{options.web_port}; check health before claiming startup. Enter stop to close hosts and recorder.", flush=True)
        input()
finally:
    for child in children:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=15)
    server.shutdown()
    scan = subprocess.run([os.sys.executable, "-B", str(root / "scripts/verify-key-absence.py")],
                          env=env, text=True, encoding="utf-8", capture_output=True)
    record("secret-scan.jsonl", scan.stdout)
    print("Exact-key verification: " + clean(scan.stdout.strip()), flush=True)
    if scan.returncode:
        raise SystemExit("Exact-key verification failed; inspect privately.")

if options.mode == "cli":
    records = output / "model-responses.jsonl"
    rows = [json.loads(line) for line in records.read_text(encoding="utf-8").splitlines()] if records.exists() else []
    passed = sum(row["httpStatus"] == 200 and row["jsonValid"] and row["actionValid"] and row["inputValid"] for row in rows)
    gate = {"calls": len(rows), "passed": passed, "minimumCalls": 10, "threshold": .9,
            "percent": round(100 * passed / len(rows), 2) if rows else 0,
            "cliExitCodes": cli_exits,
            "passedGate": len(rows) >= 10 and passed / len(rows) >= .9 and all(code == 0 for code in cli_exits)}
    record("contract-gate.json", json.dumps(gate))
    print(json.dumps(gate), flush=True)
    if not gate["passedGate"]:
        raise SystemExit("Real contract gate failed; fix and rerun. Semantic review is also required.")
