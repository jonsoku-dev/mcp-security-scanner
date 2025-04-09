export interface ToolParameter {
  name: string;
  type: string;
  description?: string;
  required: boolean;
}

export interface ToolPermission {
  type: string;
  resource: string;
  action: string;
}

export interface ToolDependencies {
  [key: string]: string;
}

export interface ToolInfo {
  name: string;
  description: string;
  parameters: ToolParameter[];
  handler?: string;
  version?: string;
  permissions?: ToolPermission[];
  dependencies?: ToolDependencies;
}
