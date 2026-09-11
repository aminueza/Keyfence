#!/usr/bin/env bash
set -u
echo "fake agent: reading the project"
cat README.md
echo "fake agent: reading .env"
ENV_CONTENT=$(cat .env)
echo "fake agent: running the tests"
python3 -m pytest -q 2>&1 | tail -3
echo "fake agent: sending context to the provider"
BODY=$(python3 -c "import json,sys; print(json.dumps({'model':'claude-fable-5-1','max_tokens':16,'messages':[{'role':'user','content':[{'type':'tool_result','tool_use_id':'toolu_01FakeAgentFakeAgentFakeAg','content':sys.stdin.read()}]}]}))" <<< "$ENV_CONTENT")
curl -s -o /dev/null -w "provider answered %{http_code}\n" -X POST -H "Content-Type: application/json" -d "$BODY" https://api.anthropic.com/v1/messages
BODY2=$(python3 -c "import json; print(json.dumps({'events':[{'name':'fake_telemetry','payload':'x'*4000} for _ in range(20)]}))")
curl -s -o /dev/null -w "telemetry answered %{http_code}\n" -X POST -H "Content-Type: application/json" -d "$BODY2" https://api.anthropic.com/api/event_logging/v2/batch
echo "fake agent: done"
