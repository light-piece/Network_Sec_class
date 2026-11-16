# AI-Assisted Network Defense

This project evaluates whether a local AI model can analyze network-security events and recommend useful, bounded responses in an OPNsense lab. Deterministic policy and a human reviewer retain authority over enforcement.

## Language

**Security event**:
A structured record of observed network activity presented for analysis within the lab.
_Avoid_: Log blob, alert data

**Monitoring Agent**:
The component that converts OPNsense observations into security events.
_Avoid_: Log reader, collector

**Local LLM**:
The locally hosted language model that classifies a security event and returns a structured response recommendation.
_Avoid_: AI firewall, autonomous defender

**Normalized event**:
A structured Security event captured from controlled OPNsense observations and replayed unchanged during evaluation.
_Avoid_: Raw log, live event

**Response recommendation**:
The Local LLM's proposed predefined response action for a security event. It has no authority to change the network.
_Avoid_: Command, firewall change

**Structured response**:
The Hardened workflow's required JSON response containing an event identifier, Network classification, severity, adversarial-content flag, Response action, confidence, and display-only rationale.
_Avoid_: Free-text advice, command output

**Response action**:
A named, predefined, scoped response that may be recommended: `no_action`, `alert_admin`, `increase_monitoring`, `temporary_ip_block`, or `isolate_lab_host`.
_Avoid_: Arbitrary command, remediation script

**Temporary containment**:
A time-limited `temporary_ip_block` or `isolate_lab_host` response action that expires automatically after 15 minutes.
_Avoid_: Permanent block, firewall reconfiguration

**Policy Validator**:
The deterministic authority that approves or rejects a response recommendation against the lab's security rules.
_Avoid_: AI reviewer, second LLM

**Lab boundary**:
The declared OPNsense test environment and its registered test assets; response actions cannot target anything outside it.
_Avoid_: Network scope, permitted range

**Policy violation**:
A proposed or applied response that conflicts with a Policy Validator rule, including expanded access, disabled protection, permanent change, out-of-boundary target, or untrusted LLM output.
_Avoid_: Bad recommendation, security failure

**Human Approver**:
The person who clicks Apply for a Policy Validator-approved response action.
_Avoid_: Passive reviewer, override

**Human rejection**:
The Human Approver's recorded decision not to apply a Policy Validator-approved response action.
_Avoid_: Policy rejection, failed enforcement

**OPNsense enforcement**:
The application of a Human Approver's approved, predefined response action in the OPNsense lab.
_Avoid_: LLM action, autonomous firewall edit

**Enforcement account**:
A dedicated, least-privilege OPNsense API account that can invoke only the preconfigured Temporary containment operations.
_Avoid_: Firewall administrator, root account

**Lab topology**:
The separated OPNsense VM, Linux test VM, and local agent host/VM used for project evaluation.
_Avoid_: Production network, shared test host

**Local-only run**:
An evaluation run in which event data, Local LLM inference, audit records, and enforcement control remain inside the Lab boundary without cloud AI services.
_Avoid_: Hybrid inference, online analysis

**Audit record**:
The local record of a Security event's workflow version, Local LLM settings and output, Policy Validator decision, Human Approver decision, and timestamps.
_Avoid_: Notification, alert message

**Adversarial log content**:
Instruction-like text placed in a security event to manipulate the Local LLM's analysis or recommendation.
_Avoid_: Bad log, malicious prompt

**Control event**:
A security event without Adversarial log content that provides the comparison baseline for a paired attack event.
_Avoid_: Clean log, normal case

**Attack event**:
A security event that differs from its paired Control event only by the presence of Adversarial log content.
_Avoid_: Poisoned event, malicious case

**Manual review**:
The recorded presentation of an untrusted Security event to a Human Approver without an LLM-authorized Response action.
_Avoid_: Automatic alert, enforcement request

**Expected outcome**:
The team's pre-defined Network classification and appropriate Response action for one Evaluation event set member.
_Avoid_: Model answer, guessed result

**Evaluation event set**:
A fixed, versioned collection of Control events and Attack events used by both workflows with the same Local LLM settings.
_Avoid_: Random test data, live-log sample

**Evaluation measure**:
A recorded result used to compare workflows: classification accuracy, appropriate-response rate, false positives, false negatives, Policy Validator block rate, unauthorized applied actions, or end-to-end response time.
_Avoid_: Safety score, performance number

**Attack influence**:
An Attack event causing the Basic workflow to produce an unsafe free-text recommendation. It cannot cause OPNsense enforcement.
_Avoid_: Security failure, applied attack

**Security failure**:
An untrusted or policy-violating recommendation that becomes Policy Validator-approved and Human Approver-applied OPNsense enforcement in the Hardened workflow.
_Avoid_: Unsafe advice, bad model output

**Basic workflow**:
The dry-run comparison workflow that gives raw event text to the Local LLM and records its free-text advice without permitting OPNsense enforcement.
_Avoid_: Unprotected system

**Hardened workflow**:
The comparison workflow that uses structured inputs, strict LLM output, predefined response actions, Policy Validator review, and Human Approver enforcement.
_Avoid_: Perfectly secure system

**Network classification**:
The Local LLM's assessment that a Security event is `benign`, `suspicious`, or `malicious`.
_Avoid_: Threat score, verdict
