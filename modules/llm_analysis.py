import os
import json
from groq import Groq
from dotenv import load_dotenv

# Load environment variables from .env file —
# this makes GROQ_API_KEY available via os.environ
load_dotenv()

def run(results: dict) -> dict:
    """
    Send the full OSINT results to the LLM and get back a structured
    threat analysis report. This is the intelligence layer that turns
    raw data into actionable insights.

    Unlike other modules, this one takes the full results dict
    as input instead of just a target string — it needs everything
    collected so far to generate a meaningful analysis.
    """

    try:
        client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

        # Convert the results dict to a clean JSON string for the prompt.
        # The LLM needs to read this as structured data, not a Python object.
        results_json = json.dumps(results, indent=2)

        # ── System prompt ─────────────────────────────────────────────────
        # Tells the LLM what role it's playing and what format to respond in.
        # Being specific here is critical — vague system prompts give vague output.
        system_prompt = """You are a cybersecurity analyst specializing in OSINT and threat intelligence.
You will be given raw OSINT data about a domain and must produce a structured threat analysis.

You must respond ONLY with a valid JSON object — no preamble, no markdown, no explanation outside the JSON.

Your response must follow this exact structure:
{
    "risk_level": "LOW | MEDIUM | HIGH | CRITICAL",
    "risk_score": <integer 0-100>,
    "summary": "<2-3 sentence overview of the target>",
    "findings": [
        {
            "category": "<category name>",
            "detail": "<what you found>",
            "severity": "INFO | LOW | MEDIUM | HIGH"
        }
    ],
    "recommendations": [
        "<actionable recommendation string>"
    ]
}

Scoring guidance:
- 0-25: LOW — nothing suspicious, well configured
- 26-50: MEDIUM — some concerns worth monitoring
- 51-75: HIGH — clear issues that need attention
- 76-100: CRITICAL — immediate action required

Base your analysis on all available data: WHOIS, DNS, ports, SSL, and geolocation.
Flag things like: expiring certs, old domains, unusual open ports, missing security records, suspicious registrars."""

        # ── User prompt ───────────────────────────────────────────────────
        # The actual data we want analyzed. Keeping system and user prompts
        # separate is best practice — system sets behavior, user provides data.
        user_prompt = f"""Analyze the following OSINT data and return your structured threat analysis:

{results_json}"""

        response = client.chat.completions.create(
            # llama-3.3-70b-versatile is Groq's best model —
            # fast, free tier, and strong enough for structured analysis
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            # temperature=0.2 keeps the output focused and consistent —
            # lower temperature = less creative, more precise, better for JSON
            temperature=0.2,
            max_tokens=1500,
        )

        # Extract the raw text response from the API response object
        raw_output = response.choices[0].message.content.strip()

        # The LLM should return pure JSON per our system prompt,
        # but sometimes it wraps it in ```json ... ``` markdown blocks.
        # Strip those out just in case.
        if raw_output.startswith("```"):
            raw_output = raw_output.split("```")[1]
            if raw_output.startswith("json"):
                raw_output = raw_output[4:]

        # Parse the cleaned string into a Python dict
        analysis = json.loads(raw_output)

        return analysis

    except json.JSONDecodeError:
        # LLM returned something that isn't valid JSON —
        # return the raw text so we can debug what it actually said
        return {"error": "LLM returned invalid JSON", "raw": raw_output}

    except Exception as e:
        return {"error": str(e)}