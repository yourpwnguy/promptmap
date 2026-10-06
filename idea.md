promptmap — Prompt Injection Scanner

Go 

LLM security. Takes a target URL of an LLM-integrated application, runs a corpus of known prompt injection payloads and mutation variants, and classifies responses to detect whether the injection succeeded.

promptmap --url https://app.com/chat --mode direct
promptmap --url https://app.com/chat --mode indirect

The interesting technical problem is detection — how do you know the injection worked? You look for instruction-following in the response when the application shouldn't be following your instructions. That's a classification problem you can solve with simple heuristics or a secondary LLM call.

Why it fits you: directly extends the mutation engine concept from redirx into a new domain. Same pattern — fuzz payloads, detect success, report findings.
