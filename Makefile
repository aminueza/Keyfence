.PHONY: test integration bench lab-smoke lab-claude lab-report demo-gif

test:
	pytest

integration:
	bash tests/integration_test.sh

bench:
	python bench/run.py

lab-smoke:
	python bench/lab/run.py --label smoke --agent "bash $(CURDIR)/bench/lab/fake_agent.sh" --linger 5 --out lab-out
	python bench/lab/report.py lab-out

lab-claude:
	python bench/lab/run.py --label claude-code --agent 'claude -p --allowedTools Read,Edit,Bash "{prompt}"' --runs 3 --out lab-out
	python bench/lab/report.py lab-out

lab-report:
	python bench/lab/report.py lab-out

demo-gif:
	python tools/demo_gif.py docs/keyfence-demo.gif
