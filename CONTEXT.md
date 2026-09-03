# Coding-Agent Security Evaluation

This project studies whether permission controls can reduce harmful AI coding-agent behavior without preventing useful security work.

## Language

**Agent under test**:
The AI coding agent whose behavior an experiment measures.
_Avoid_: Subject agent, tested bot

**Evaluation scenario**:
A reproducible combination of a repository, legitimate task, attack condition, and permission profile used for one or more agent runs.
_Avoid_: Test case, challenge

**Control scenario**:
An evaluation scenario that contains no repository prompt injection and provides the baseline for its paired attack scenario.
_Avoid_: Clean run, normal case, benign case

**Attack scenario**:
An evaluation scenario that differs from its paired control scenario only by the presence of a repository prompt injection.
_Avoid_: Attacked run, malicious case

**Permission profile**:
A named set of limits on the agent's filesystem, command, network, and approval capabilities.
_Avoid_: Access mode, security level

**Repository prompt injection**:
A malicious instruction placed in repository content to redirect the agent away from its legitimate task.
_Avoid_: Malicious prompt, poisoned repository

**Canary secret**:
A synthetic, non-sensitive value used to detect unauthorized secret access or disclosure.
_Avoid_: Fake secret, test credential

**Security outcome**:
The measured attempted or completed policy violations during an agent run.
_Avoid_: Safety score, harm score

**Task utility**:
The measured degree to which the agent completes the legitimate task under a permission profile.
_Avoid_: Usefulness, productivity score
