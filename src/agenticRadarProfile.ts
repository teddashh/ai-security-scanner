import type { AgenticRadarFramework } from "./types";

export const agenticRadarFrameworks: ReadonlyArray<{ id: AgenticRadarFramework; label: string }> = [
  { id: "langgraph", label: "LangGraph" },
  { id: "crewai", label: "CrewAI" },
  { id: "n8n", label: "n8n" },
  { id: "openai-agents", label: "OpenAI Agents" },
  { id: "autogen", label: "AutoGen" },
];

export const agenticRadarFramework = (value: unknown): AgenticRadarFramework | undefined =>
  agenticRadarFrameworks.find((framework) => framework.id === value)?.id;
