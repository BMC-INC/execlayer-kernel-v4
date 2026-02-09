# ExecLayer Kernel V4

ExecLayer Kernel V4 is a React + Vite front-end for exercising the ExecLayer governance **kernel** and visualizing how intents are evaluated, blueprints are generated, and enforcement decisions are made.

## Features

- Kernel V4 chat interface for entering principal + intent
- Governance evaluation state machine (IDLE → GOVERNANCE_EVAL)
- Receipt chain panel showing blueprint anchoring
- Forensic event log for enforcement and failures
- Backend API at `/api/kernel` that calls Gemini and returns:
  - `briefingText` – human-readable governance briefing
  - `blueprint` – V3.x blueprint JSON with governance DSL

## Tech Stack

- React + Vite
- Tailwind CSS
- Node.js API route (`api/kernel.js`)
- Gemini 2.5 (via `GEMINI_API_KEY`)

## Local Development

```bash
npm install
npm run dev

