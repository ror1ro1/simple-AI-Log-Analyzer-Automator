markdown
# AI Log Analyzer & Automator

A Python-based automated ETL pipeline that processes raw system security logs, leverages the Google Gemini 2.5 API for intelligent agentic threat classification, and loads the structured analytical insights into a local SQL database.

## Features
- **Extract**: Simulates fetching raw, unstructured log data from enterprise sources.
- **Transform**: Uses the `google-genai` SDK and modern structured outputs to parse text, assess threat severity, and generate remediation actions.
- **Load**: Commits the verified and structured security incident attributes into an SQLite relational database.

## Tech Stack
- **Language**: Python 3
- **AI Core**: Google Gemini 2.5 Flash API
- **Database**: SQL / SQLite3
