import { deployment } from '../deployment';
import type { Env } from '../env';
import type { ToolDef } from './types';

export type { Caller, ToolContext, ToolDef, ToolOutcome } from './types';

/** The tools this deployment carries. Policy then narrows them per agent. */
export function toolsFor(_env: Env): Record<string, ToolDef> {
  return deployment().tools;
}
