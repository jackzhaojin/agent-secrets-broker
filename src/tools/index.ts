import type { Env } from '../env';
import { CORE_TOOLS } from './core';
import { MOCKGIT_TOOLS } from './mockgit';
import type { ToolDef } from './types';

export type { Caller, ToolContext, ToolDef, ToolOutcome } from './types';

const SANDBOX_TOOLS: Record<string, ToolDef> = { ...CORE_TOOLS, ...MOCKGIT_TOOLS };

/** The tools this deployment carries. Policy then narrows them per agent. */
export function toolsFor(_env: Env): Record<string, ToolDef> {
  return SANDBOX_TOOLS;
}
