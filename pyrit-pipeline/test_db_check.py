"""Check latest attack results - fixed converter run."""
import sys
import os

sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, ".")

from pyrit.memory import CentralMemory, SQLiteMemory

db_path = "outputs/db/redteam_20260815_224706.db"
mem = SQLiteMemory(db_path=db_path)
CentralMemory.set_memory_instance(mem)
memory = CentralMemory.get_memory_instance()

results = memory.get_attack_results()
print(f"Total attack results: {len(results)}")

from collections import Counter
outcome_counts = Counter(str(r.outcome) for r in results)
print(f"\nOutcome distribution:")
for outcome, count in outcome_counts.most_common():
    print(f"  {outcome}: {count}")

for i, ar in enumerate(results[:5]):
    print(f"\n=== Attack Result {i} ===")
    print(f"  Outcome: {ar.outcome}")
    print(f"  Reason: {(ar.outcome_reason or 'N/A')[:200]}")
    conv_id = ar.conversation_id
    
    if conv_id:
        msgs = list(memory.get_conversation_messages(conversation_id=conv_id))
        for msg in msgs:
            for piece in msg.message_pieces:
                role = piece.role
                val = (piece.converted_value or "N/A")[:200]
                safe_val = val.encode('ascii', 'replace').decode('ascii')
                print(f"  [{role}] {safe_val}")
