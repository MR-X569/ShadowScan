export interface PriorityFinding {
  finding_id: number;
  priority: number;
  title: string;
  reason: string;
}

export interface FindingRelationship {
  finding_ids: number[];
  explanation: string;
}

export interface RemediationStep {
  priority: number;
  action: string;
  reason: string;
}

export interface ScanAIAnalysis {
  overall_assessment: string;
  risk_level: string;
  executive_summary: string;
  priority_findings: PriorityFinding[];
  relationships: FindingRelationship[];
  remediation_plan: RemediationStep[];
  verification_steps: string[];
  ai_status: 'ready' | 'unavailable' | 'disabled' | 'error';
  model_used: string;
}

export interface FindingAIExplanation {
  finding_id: number;
  title: string;
  severity: string;
  meaning: string;
  impact_analysis: string;
  severity_justification: string;
  remediation_guide: string;
  verification_method: string;
  ai_status: 'ready' | 'unavailable' | 'disabled' | 'error';
  model_used: string;
}

export interface AIChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface AIChatRequest {
  message: string;
  history?: AIChatMessage[];
}

export interface AIChatResponse {
  response: string;
  is_refusal: boolean;
  ai_status: 'ready' | 'unavailable' | 'disabled' | 'error';
  model_used: string;
}

export interface AIStatus {
  enabled: boolean;
  provider: string;
  available: boolean;
  model: string;
  base_url: string;
}
