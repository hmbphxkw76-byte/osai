"""Check attack results from CentralMemory - fixed version."""
import sys
sys.path.insert(0, ".")

from pyrit.memory import CentralMemory, SQLiteMemory

mem = SQLiteMemory()
CentralMemory.set_memory_instance(mem)
memory = CentralMemory.get_memory_instance()

results = memory.get_attack_results()
print(f"Total attack results: {len(results)}")

# Count outcomes
from collections import Counter
outcome_counts = Counter(str(r.outcome) for r in results)
print(f"\nOutcome distribution:")
for outcome, count in outcome_counts.most_common():
    print(f"  {outcome}: {count}")

# Show last 10 results (most recent)
print(f"\n=== Last 10 Attack Results (most recent) ===")
for i, ar in enumerate(results[-10:]):
    print(f"\n--- Result {len(results)-10+i} ---")
    print(f"  Outcome: {ar.outcome}")
    reason = ar.outcome_reason or "N/A"
    print(f"  Reason: {reason[:200]}")
    conv_id = ar.conversation_id
    
    if conv_id:
        msgs = list(memory.get_conversation_messages(conversation_id=conv_id))
        for msg in msgs:
            for piece in msg.message_pieces:
                role = piece.role
                val = (piece.converted_value or "N/A")[:200]
                print(f"  [{role}] {val}")
