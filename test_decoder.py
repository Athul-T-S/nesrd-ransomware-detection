import subprocess
test_log = '{"decision": "ISOLATE", "agent_id": "vm-win10-001"}'
with open("/tmp/test_nesrd.log", "w") as f:
    f.write(test_log + "\n")
print("Test log written:", test_log)
