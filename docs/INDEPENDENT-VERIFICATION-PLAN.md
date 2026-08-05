# Independent verification architecture

The active architecture and implementation authority is CAP's
[`docs/verification/INDEPENDENT-VERIFICATION-PLAN.md`](../../../cap/docs/verification/INDEPENDENT-VERIFICATION-PLAN.md).

Prove-It is only an adversarial demonstration workload. It does not own a verifier, trust policy,
expected measurement, or authoritative verdict. `PROVE_IT_ADVERSARIAL_DEMO=1` enables deliberately
false tenant and appraiser `PASS` claims used to prove that CAP's reserved route and independently
run verifier ignore them.
